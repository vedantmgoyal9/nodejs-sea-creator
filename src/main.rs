#![doc = include_str!("../README.md")]
#![deny(clippy::all, clippy::pedantic)]
#![deny(missing_docs)]

use clap::Parser;
use exe::{Buffer, ImageDirectoryEntry, PE, RVA, VecPE};
use goblin::mach::{Mach, constants::SEG_LINKEDIT, load_command::CommandVariant};
use sha2::Digest;
use std::{
    fmt::Display,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;

// ============================================================================================== //

enum Target {
    WinArm64,
    WinX64,
    LinuxArm64,
    LinuxX64,
    DarwinArm64,
    DarwinX64,
}

impl Default for Target {
    fn default() -> Self {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            Target::DarwinArm64
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            Target::DarwinX64
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Target::LinuxArm64
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Target::LinuxX64
        }
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            Target::WinArm64
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            Target::WinX64
        }
    }
}

impl FromStr for Target {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "darwin-arm64" => Ok(Target::DarwinArm64),
            "darwin-x64" => Ok(Target::DarwinX64),
            "linux-arm64" => Ok(Target::LinuxArm64),
            "linux-x64" => Ok(Target::LinuxX64),
            "win-arm64" => Ok(Target::WinArm64),
            "win-x64" => Ok(Target::WinX64),
            _ => Err(format!(
                "Invalid platform-arch: {}\nSupported values: {}, {}, {}, {}, {}, {}",
                s,
                Target::DarwinArm64,
                Target::DarwinX64,
                Target::LinuxArm64,
                Target::LinuxX64,
                Target::WinArm64,
                Target::WinX64
            )),
        }
    }
}

impl Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::DarwinArm64 => write!(f, "darwin-arm64"),
            Target::DarwinX64 => write!(f, "darwin-x64"),
            Target::LinuxArm64 => write!(f, "linux-arm64"),
            Target::LinuxX64 => write!(f, "linux-x64"),
            Target::WinArm64 => write!(f, "win-arm64"),
            Target::WinX64 => write!(f, "win-x64"),
        }
    }
}

impl PartialEq for Target {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Target::WinArm64, Target::WinArm64) => true,
            (Target::WinX64, Target::WinX64) => true,
            (Target::LinuxArm64, Target::LinuxArm64) => true,
            (Target::LinuxX64, Target::LinuxX64) => true,
            (Target::DarwinArm64, Target::DarwinArm64) => true,
            (Target::DarwinX64, Target::DarwinX64) => true,
            _ => false,
        }
    }
}

// ============================================================================================== //

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(author, version, about)]
struct Cli {
    /// Path to sea-config.json file
    #[arg(value_name = "SEA_CONFIG_PATH", default_value = "sea-config.json")]
    sea_config: PathBuf,

    /// Target platform (defaults to current platform if not specified)
    #[arg(short = 't', long = "target")]
    target: Option<String>,

    /// Output path of the generated Node.js SEA binary
    #[arg(short = 'o', long = "output")]
    output: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // get node version, also check if it's >=22
    let node_version = match Command::new("node").arg("--version").output() {
        Ok(out) => {
            // we know that the output will be a valid utf-8 string, so we just `unwrap()`.
            let version = String::from_utf8(out.stdout).unwrap();
            if version
                .trim_start_matches("v")
                .split(".")
                .next()
                .unwrap()
                .parse::<u16>()
                .unwrap_or_default()
                < 22
            {
                eprintln!("Node.js version >=22 is required.");
                std::process::exit(1);
            }
            version.trim().to_string()
        }
        Err(err) => {
            eprintln!("Error executing `node --version`: {}", err);
            std::process::exit(1);
        }
    };

    // parse target string to Target enum, else get current platform
    let target = match cli.target {
        Some(t) => match t.parse::<Target>() {
            Ok(target) => target,
            Err(err) => {
                eprintln!("{}", err);
                std::process::exit(1);
            }
        },
        None => Target::default(),
    };

    // read package.json to get project name and version for naming the output file
    let package_json = serde_json::from_str::<serde_json::Value>(
        std::fs::read_to_string("package.json")
            .unwrap_or_else(|err| {
                eprintln!("error reading contents of package.json: {err}");
                std::process::exit(1);
            })
            .as_str(),
    )
    .unwrap();

    // working directory for this tool
    let working_dir = PathBuf::from(env!("CARGO_PKG_NAME"));

    // path of the final nodejs sea binary that will be created
    let output_path = match cli.output {
        Some(path) => PathBuf::from(path),
        None => working_dir.join(format!(
            "{}_v{}_{target}_node{}{}",
            package_json["name"].as_str().unwrap(),
            package_json["version"].as_str().unwrap(),
            node_version.trim_start_matches("v"),
            match target {
                Target::WinArm64 | Target::WinX64 => ".exe",
                _ => "", // no extension for other platforms
            }
        )),
    };

    // read and parse nodejs sea config
    let sea_config = serde_json::from_str::<serde_json::Value>(
        std::fs::read_to_string(&cli.sea_config)
            .unwrap_or_else(|err| {
                eprintln!(
                    "error reading contents of {}: {err}",
                    cli.sea_config.display()
                );
                std::process::exit(1);
            })
            .as_str(),
    )
    .unwrap();

    // check if sea blob path (output field in sea-config.json) is what we expect
    let expected_path = format!("{}/sea-prep.blob", env!("CARGO_PKG_NAME"));
    if sea_config["output"].as_str().unwrap() != expected_path {
        eprintln!("The `output` field in sea-config.json should be set to `{expected_path}`.");
        std::process::exit(1);
    }

    // when target is not same as host, exit if useCodeCache or useSnapshot is set to true
    if target != Target::default()
        // https://nodejs.org/api/single-executable-applications.html#generating-single-executable-preparation-blobs
        // default values for useCodeCache and useSnapshot are false
        && (sea_config["useCodeCache"].as_bool().unwrap_or(false)
            || sea_config["useSnapshot"].as_bool().unwrap_or(false))
    {
        eprintln!(
            "When generating cross-platform SEAs (e.g., generating a SEA for linux-x64 on \
            darwin-arm64), `useCodeCache` and `useSnapshot` must be set to false to avoid \
            generating incompatible executables. Since code cache and snapshots can only be loaded \
            on the same platform where they are compiled, the generated executable might crash on \
            startup when trying to load code cache or snapshots built on a different platform."
        );
        std::process::exit(1);
    }

    // path to the prepared node binary i.e. original nodejs with code signature removed
    let mut prepared_node = working_dir.join("nodejs-prepared").join(format!(
        "node-{node_version}-{target}{}",
        match target {
            Target::WinArm64 | Target::WinX64 => ".exe",
            _ => "", // no extension for other platforms
        }
    ));

    if !prepared_node.exists() {
        // create the directories for the prepared node binary
        std::fs::create_dir_all(prepared_node.parent().unwrap()).unwrap();

        // if target is default, use the installed node binary
        // else, download the node binary from nodejs.org
        if target == Target::default() {
            println!("Since target is same as host, using installed Node.js binary...");
            let system_node_path = Command::new("node")
                .arg("-e")
                .arg("console.log(process.execPath)")
                .output()
                .unwrap();
            std::fs::copy(
                Path::new(String::from_utf8(system_node_path.stdout).unwrap().trim()),
                &prepared_node,
            )
            .unwrap();

            // update permissions of the copied node binary on darwin and linux, so
            // permission denied (os error 13) is not thrown when removing code signature
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                let mut permissions = std::fs::metadata(&prepared_node).unwrap().permissions();
                permissions.set_mode(0o755); // rwxr-xr-x
                std::fs::set_permissions(&prepared_node, permissions).unwrap();
            }
        } else {
            let mut download_url = format!("https://nodejs.org/dist/{node_version}/");
            let download_url_prefix = download_url.clone();
            match target {
                Target::WinArm64 | Target::WinX64 => {
                    download_url.push_str(format!("{target}/node.exe").as_str())
                }
                _ => download_url.push_str(format!("node-{node_version}-{target}.tar.gz").as_str()),
            };
            println!("Downloading {}...", download_url);

            // for linux and darwin, nodejs.org provides a tar.gz archive
            if target != Target::WinArm64 && target != Target::WinX64 {
                prepared_node.set_file_name(format!("node-{node_version}-{target}.tar.gz"));
            }

            // download the node binary
            reqwest::blocking::get(&download_url)
                .unwrap()
                .copy_to(&mut std::fs::File::create(&prepared_node).unwrap())
                .unwrap();

            // calculate sha256 hash of the downloaded node binary
            let mut hasher = sha2::Sha256::new();
            hasher.update(std::fs::read(&prepared_node).unwrap());
            let actual_hash = format!("{:x}", hasher.finalize());

            // get the expected hash from nodejs.org
            let expected_hash = reqwest::blocking::get(format!(
                "https://nodejs.org/dist/{node_version}/SHASUMS256.txt"
            ))
            .unwrap()
            .text()
            .unwrap()
            .lines()
            .find(|line| {
                line.ends_with(download_url.trim_start_matches(download_url_prefix.as_str()))
            })
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();

            // if the hashes do not match, exit with an error, else proceed
            if actual_hash != expected_hash {
                println!("❌ SHA-256 hashes do not match.");
                println!("Actual: {}", actual_hash);
                println!("Expected: {}", expected_hash);
                println!(
                    "Please remove `{}` directory and try again.",
                    env!("CARGO_PKG_NAME")
                );
                std::process::exit(1);
            }
            println!("✅ SHA-256 hashes match.");

            // extract the node binary from the tar.gz file, only for linux and darwin
            if target != Target::WinArm64 && target != Target::WinX64 {
                let gz = flate2::read::GzDecoder::new(std::fs::File::open(&prepared_node).unwrap());
                let mut tar = tar::Archive::new(gz);

                // set prepared_node to "binary" (drop .tar.gz extension) after opening the archive
                prepared_node.set_file_name(format!("node-{node_version}-{target}"));

                // extract the node binary from the tar.gz archive
                for entry in tar.entries().unwrap() {
                    let mut entry = entry.unwrap();
                    if entry.path().unwrap().eq(Path::new(
                        format!("node-{node_version}-{target}/bin/node").as_str(),
                    )) {
                        println!("Extracting {}...", entry.path().unwrap().display());
                        entry.unpack(prepared_node.as_path()).unwrap();
                        break;
                    }
                }
            }
        };

        // remove signature from the macos and windows node binaries
        match target {
            // source: https://github.com/AlexanderOMara/macho-unsign/blob/master/src/unsign.ts
            Target::DarwinArm64 | Target::DarwinX64 => {
                let buffer = std::fs::read(prepared_node.as_path()).unwrap();
                let mut cs_command_offset = 0;
                let mut cs_command_size = 0;
                let mut linkedit64_size_offset = 0;
                let mut linkedit64_size = 0;
                let mut end = 0;
                let mut far = |offset: u64| -> () {
                    if offset > end {
                        end = offset;
                    }
                };

                match Mach::parse(&buffer) {
                    Ok(Mach::Binary(macho)) => {
                        if !macho.is_64 {
                            panic!(
                                "Removing code signature from 32-bit Mach-O files is not supported yet."
                            );
                        }

                        // https://en.wikipedia.org/wiki/Mach-O#Segment_load_command
                        // Offset(32-bit) Bytes(32-bit) Offset(64-bit) Bytes(64-bit) Description
                        // 0              4	            0              4             0x00000001 (Command type 32-bit)
                        //                                                           0x00000019 (Command type 64-bit)
                        // 4              4             4              4             Command size
                        // 8              16            8              16            Segment name
                        // 24             4             24             8             Address
                        // 28             4             32             8             Address size
                        // 32             4             40             8             File offset
                        // 36             4             48             8             Size (bytes from file offset)
                        // 40             4             56             4             Maximum virtual memory protections
                        // 44             4             60             4             Initial virtual memory protections
                        // 48             4             64             4             Number of sections
                        // 52             4             68             4             Flag32
                        macho.load_commands.iter().for_each(|lc| {
                            match lc.command {
                                CommandVariant::Segment64(seg) => {
                                    if seg.segname.starts_with(SEG_LINKEDIT.as_bytes()) {
                                        linkedit64_size_offset = lc.offset + 48;
                                        linkedit64_size = seg.filesize;
                                        return;
                                    }
                                    far(u64::from(seg.fileoff + seg.filesize));
                                }
                                CommandVariant::DyldInfo(dyld)
                                | CommandVariant::DyldInfoOnly(dyld) => {
                                    // Rebase, Binding, Weak Binding, Lazy Binding, and Export.
                                    far(u64::from(dyld.rebase_off + dyld.rebase_size));
                                    far(u64::from(dyld.bind_off + dyld.bind_size));
                                    far(u64::from(dyld.weak_bind_off + dyld.weak_bind_size));
                                    far(u64::from(dyld.lazy_bind_off + dyld.lazy_bind_size));
                                    far(u64::from(dyld.export_off + dyld.export_size));
                                }
                                CommandVariant::Symtab(symtab) => {
                                    far(u64::from(symtab.symoff + symtab.nsyms * 12));
                                    far(u64::from(symtab.stroff + symtab.strsize));
                                }
                                CommandVariant::Dysymtab(dysymtab) => {
                                    far(u64::from(dysymtab.tocoff + dysymtab.ntoc * 4))
                                }
                                CommandVariant::FunctionStarts(func) => {
                                    far(u64::from(func.dataoff + func.datasize))
                                }
                                CommandVariant::DataInCode(dic) => {
                                    far(u64::from(dic.dataoff + dic.datasize))
                                }
                                CommandVariant::EncryptionInfo32(enc) => {
                                    far(u64::from(enc.cryptoff + enc.cryptsize))
                                }

                                CommandVariant::EncryptionInfo64(enc) => {
                                    far(u64::from(enc.cryptoff + enc.cryptsize))
                                }
                                CommandVariant::CodeSignature(cs) => {
                                    cs_command_offset = lc.offset;
                                    cs_command_size = cs.cmdsize;
                                }
                                _ => {} // do nothing
                            }
                        });

                        let reduced = buffer.len() as u64 - end;
                        let mut new_buffer = buffer.clone();
                        new_buffer.resize(end as usize, 0);

                        if linkedit64_size_offset != 0 {
                            new_buffer
                                .get_mut(linkedit64_size_offset..linkedit64_size_offset + 8)
                                .unwrap()
                                .copy_from_slice(&(linkedit64_size - reduced).to_le_bytes());
                        }

                        new_buffer
                            .get_mut(
                                cs_command_offset..cs_command_offset + cs_command_size as usize,
                            )
                            .unwrap()
                            .copy_from_slice(&vec![0u8; cs_command_size as usize]);

                        // https://en.wikipedia.org/wiki/Mach-O#Mach-O_header
                        // Offset Bytes Description
                        // 0      4     Magic number
                        // 4      4     CPU type
                        // 8      4     CPU subtype
                        // 12     4     File type
                        // 16     4     Number of load commands
                        // 20     4     Size of load commands
                        // 24     4     Flags
                        // 28     4     Reserved (64-bit only)

                        // reduce the number of load commands by one
                        new_buffer
                            .get_mut(16..20)
                            .unwrap()
                            .clone_from_slice(&(macho.header.ncmds as u32 - 1).to_le_bytes());

                        // shrinks the size of load commands by the size of the code signature
                        new_buffer.get_mut(20..24).unwrap().clone_from_slice(
                            &(macho.header.sizeofcmds - cs_command_size).to_le_bytes(),
                        );

                        std::fs::write(prepared_node.as_path(), new_buffer).unwrap_or_else(|err| {
                            eprintln!("failed to save nodejs binary with removed signature: {err}");
                            std::process::exit(1);
                        });
                    }
                    Ok(Mach::Fat(_)) => panic!(
                        "Removing code signature from fat Mach-O files is not supported yet."
                    ),
                    Err(err) => {
                        panic!("Error parsing Mach-O file: {:?}", err);
                    }
                }
            }
            Target::WinArm64 | Target::WinX64 => {
                let mut pefile = VecPE::from_disk_file(prepared_node.as_path()).unwrap();

                let addr = pefile
                    .get_data_directory(ImageDirectoryEntry::Security)
                    .unwrap()
                    .virtual_address;

                pefile
                    .get_mut_data_directory(ImageDirectoryEntry::Security)
                    .unwrap()
                    .virtual_address = RVA(0);

                pefile
                    .get_mut_data_directory(ImageDirectoryEntry::Security)
                    .unwrap()
                    .size = 0;

                if addr != RVA(0) {
                    pefile.resize(addr.into(), 0);
                }

                pefile
                    .get_mut_nt_headers_64()
                    .unwrap()
                    .optional_header
                    .checksum = pefile.calculate_checksum().unwrap();

                pefile.save(prepared_node.as_path()).unwrap_or_else(|err| {
                    eprintln!("failed to save nodejs binary with removed signature: {err}");
                    std::process::exit(1);
                });
            }
            _ => {} // we don't need to do anything for Linux
        }
    }

    println!("Node.js binary: {}", prepared_node.display());

    // run `node --experimental-sea-config` to generate the blob to be injected
    println!(
        "Running `node --experimental-sea-config {}`...",
        cli.sea_config.display()
    );
    let generate_sea_blob_cmd = Command::new("node")
        .arg("--experimental-sea-config")
        .arg(format!("{}", cli.sea_config.display()))
        .status()
        .unwrap();
    if !generate_sea_blob_cmd.success() {
        std::process::exit(generate_sea_blob_cmd.code().unwrap());
    }

    // since postject updates the binary in place, we make a copy of the binary
    // and execute postject on it, so we can re-use the prepared node binary in subsequent
    // runs, avoiding the need to download nodejs and removing code signature from it every time
    std::fs::copy(&prepared_node, &output_path).unwrap();

    // generate postject command and run it
    let mut postject_cmd = format!(
        "postject {} NODE_SEA_BLOB {} --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
        output_path.display(),
        working_dir.join("sea-prep.blob").display()
    );
    if target == Target::DarwinArm64 || target == Target::DarwinX64 {
        postject_cmd.push_str(" --macho-segment-name NODE_SEA");
    }
    println!("Running `npx --yes {postject_cmd}`...");

    // called `Result::unwrap()` on an `Err` value: Error { kind: NotFound, message: "program not found" }
    // Command::new("npx") does NOT work on Windows and produces the above error
    // the PATH contains npx.cmd (not npx.exe), so we must use Command::new("npx.cmd") on Windows
    let npx_postject_cmd = Command::new(if cfg!(windows) { "npx.cmd" } else { "npx" })
        .arg("--yes")
        .args(postject_cmd.split_whitespace())
        .status()
        .unwrap();
    if !npx_postject_cmd.success() {
        std::process::exit(npx_postject_cmd.code().unwrap());
    }

    // sign the nodejs sea binary with ad-hoc signature, if target is darwin
    // note: signing is platform-independent. doesn't depend on apple's codesign 🥳
    if target == Target::DarwinArm64 || target == Target::DarwinX64 {
        println!(
            "Since macOS only runs signed binaries, signing the binary with ad-hoc signature..."
        );
        println!(
            "Note: you may still need to sign the binary with your apple signing certificate later."
        );
        let signing_settings = apple_codesign::SigningSettings::default();
        let unified_signer = apple_codesign::UnifiedSigner::new(signing_settings);
        unified_signer.sign_path_in_place(output_path).unwrap();
    }
}

// ============================================================================================== //
