/*!
Many of the inputs to package builds are not source files tracked within the git
repository, but large binary artifacts such as tar archives that are independently
distributed by an upstream project.

This module provides the ability to retrieve and validate these external files,
given the (name, url, hash) data that uniquely identifies each file.

It implements a two-tier approach to retrieval: files are first pulled from the
"lookaside" cache and only fetched from the upstream site if that access fails.

*/
pub(crate) mod error;

use error::Result;

use super::manifest;
use r13y::Repack;
use sha2::{Digest, Sha512};
use snafu::{ensure, OptionExt, ResultExt};
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

static LOOKASIDE_CACHE: &str = "https://cache.bottlerocket.aws";

pub(crate) struct LookasideCache;

impl LookasideCache {
    /// Fetch files stored out-of-tree and ensure they match the stored hash.
    pub(crate) fn fetch(files: &[manifest::ExternalFile]) -> Result<Self> {
        for f in files {
            let url_file_name = Self::extract_file_name(&f.url)?;
            let path = &f.path.as_ref().unwrap_or_else(|| &url_file_name);
            ensure!(
                path.components().count() == 1,
                error::ExternalFileName { path }
            );

            let hash = &f.sha512;
            if path.is_file() {
                match Self::verify_file(path, hash) {
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("{}", e);
                        eprintln!("removing invalid on-disk file: {}", &path.display());
                        fs::remove_file(path).context(error::ExternalFileDelete { path })?;
                    }
                }
            }

            let name = path.display();
            let tmp = PathBuf::from(format!(".{}", name));

            // first check the lookaside cache
            let url = format!("{}/{}/{}/{}", LOOKASIDE_CACHE.to_string(), name, hash, name);
            match Self::fetch_file(&url, &tmp, hash) {
                Ok(_) => {
                    fs::rename(&tmp, path).context(error::ExternalFileRename { path: &tmp })?;
                    continue;
                }
                Err(e) => {
                    eprintln!("{}", e);
                }
            }

            // next check with upstream, if permitted
            if std::env::var("BUILDSYS_UPSTREAM_SOURCE_FALLBACK") == Ok("true".to_string()) {
                println!("Fetching {:?} from upstream source", url_file_name);
                Self::fetch_file(&f.url, &tmp, hash)?;
                fs::rename(&tmp, path).context(error::ExternalFileRename { path: &tmp })?;
            }
        }

        Ok(Self)
    }

    /// Retrieves a file from the specified URL and write it to the given path,
    /// then verifies the contents against the SHA-512 hash provided.
    fn fetch_file<P: AsRef<Path>>(url: &str, path: P, hash: &str) -> Result<()> {
        let path = path.as_ref();
        let mut resp = reqwest::blocking::get(url).context(error::ExternalFileRequest { url })?;
        let status = resp.status();
        ensure!(
            status.is_success(),
            error::ExternalFileFetch { url, status }
        );

        let f = File::create(path).context(error::ExternalFileOpen { path })?;
        let mut f = BufWriter::new(f);
        resp.copy_to(&mut f)
            .context(error::ExternalFileSave { path })?;
        drop(f);

        // If we know the source to require the use of a repacked archive, then
        // do so. For example, GitHub generates archives on the fly and produce
        // a changed hash on future fetches.
        //
        // Lookaside cache archives are not repacked, they are checked by the
        // below verification.
        let file_url = url.parse().context(error::ExternalFileUrl { url })?;

        let original = Self::verify_file(path, hash);
        let repacker = r13y::for_source(&file_url);
        match (original, repacker) {
            // Downloaded file is verified.
            (Ok(_), _) => Ok(()),
            // Unverified, downloaded file can be repacked - try verifying repacked result.
            (Err(error::Error::ExternalFileVerify { .. }), Some(p)) => {
                eprintln!("repacking into reproducible archive using {:?}", p);
                let repacked = p.repack(&path)?;
                match Self::verify_file(&repacked, hash) {
                    Ok(_) => {
                        fs::rename(&repacked, &path)
                            .context(error::ExternalFileRename { path: &repacked })?;
                        Ok(())
                    }
                    Err(e) => {
                        fs::remove_file(&repacked)
                            .context(error::ExternalFileDelete { path: &repacked })?;
                        Err(e)
                    }
                }
            }
            // Other errors don't indicate a repack can succeed, bail.
            (Err(e), _) => {
                fs::remove_file(path).context(error::ExternalFileDelete { path })?;
                Err(e)
            }
        }
    }

    fn extract_file_name(url: &str) -> Result<PathBuf> {
        let parsed = reqwest::Url::parse(url).context(error::ExternalFileUrl { url })?;
        let name = parsed
            .path_segments()
            .context(error::ExternalFileName { path: url })?
            .last()
            .context(error::ExternalFileName { path: url })?;
        Ok(name.into())
    }

    /// Reads a file from disk and compares it to the expected SHA-512 hash.
    fn verify_file<P: AsRef<Path>>(path: P, hash: &str) -> Result<()> {
        let path = path.as_ref();
        let mut f = File::open(path).context(error::ExternalFileOpen { path })?;
        let mut d = Sha512::new();

        io::copy(&mut f, &mut d).context(error::ExternalFileLoad { path })?;
        let digest = hex::encode(d.finalize());

        ensure!(digest == hash, error::ExternalFileVerify { path, hash });
        Ok(())
    }
}

mod r13y {
    use super::error::{self, Result};
    use duct::cmd;

    use snafu::ResultExt;
    use std::path::{Path, PathBuf};
    use std::{fmt::Debug, fs};

    pub(crate) fn for_source(url: &url::Url) -> Option<impl Repack + Debug> {
        let is_github = url
            .host()
            .map(|h| h.to_string() == "github.com")
            .unwrap_or_default();
        let is_tar_gz = url
            .path_segments()
            .map(|ps| {
                ps.last()
                    .map(|seg| seg.ends_with(".tar.gz"))
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        if is_github && is_tar_gz {
            return Some(TarGz);
        }

        None
    }

    pub(crate) trait Repack {
        fn repack<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf>;
    }

    #[derive(Debug)]
    pub(crate) struct TarGz;

    impl Repack for TarGz {
        fn repack<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
            let tmp: PathBuf = ".r13y".into();
            let unpack = tmp.join("input");
            let repack = tmp.join("repack.tar");

            fs::create_dir(&tmp).expect("dir");
            fs::create_dir(&unpack).expect("input unpack dir");

            let unpack_cmd = cmd!(
                "tar",
                "-x",
                "-f",
                path.as_ref().to_path_buf(),
                "-C",
                &unpack,
            );
            let repack_cmd = cmd!(
                "tar",
                "--sort=name",
                "--mtime=@0",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
                "-C",
                &unpack,
                "-c",
                "-f",
                &repack,
                // TODO: determine if this is an issue - we'll have to repack
                // existing tars to efficiently use em.
                "."
            );
            let compress_cmd = cmd!("gzip", "--no-name", &repack);

            let repacked_out: PathBuf = ".repacked.tar.gz".into();
            let ret = unpack_cmd
                .run()
                .context(error::ExternalFileLoad {
                    path: path.as_ref(),
                })
                .and_then(|_| {
                    repack_cmd.run().context(error::ExternalFileLoad {
                        path: path.as_ref(),
                    })
                })
                .and_then(|_| {
                    compress_cmd.run().context(error::ExternalFileLoad {
                        path: path.as_ref(),
                    })
                })
                .and_then(|_| {
                    fs::rename(&repack.with_extension("tar.gz"), &repacked_out).context(
                        error::ExternalFileRename {
                            path: &repacked_out,
                        },
                    )
                });

            let rmdir = fs::remove_dir_all(&tmp).context(error::ExternalFileDelete { path: &tmp });

            match ret {
                Ok(_) => rmdir.map(|_| repacked_out),
                Err(e) => Err(e),
            }
        }
    }
}
