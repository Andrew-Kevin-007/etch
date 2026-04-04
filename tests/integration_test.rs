use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_end_to_end_sign_verify() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "hello world").unwrap();

    let etch_exe = env!("CARGO_BIN_EXE_etch");
    let home_dir = tempdir().unwrap();

    // 1. Init identity
    let id_path = home_dir.path().join("id.json");
    let output = Command::new(&etch_exe)
        .arg("init")
        .env("ETCH_IDENTITY_PATH", &id_path)
        .output()
        .expect("failed to execute init");
    assert!(output.status.success());

    // 2. Sign file
    let output = Command::new(&etch_exe)
        .arg("sign")
        .arg(&file_path)
        .arg("--force")
        .arg("--name")
        .arg("Test Name")
        .arg("--project")
        .arg("Test Project")
        .arg("--domain")
        .arg("Test Domain")
        .env("ETCH_IDENTITY_PATH", &id_path)
        .output()
        .expect("failed to execute sign");
    assert!(output.status.success());
    assert!(file_path.with_extension("txt.etch").exists());

    // 3. Verify file
    let output = Command::new(&etch_exe)
        .arg("verify")
        .arg(&file_path)
        .env("ETCH_IDENTITY_PATH", &id_path)
        .output()
        .expect("failed to execute verify");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AUTHORSHIP VERIFIED  ✓"));
}

#[test]
fn test_modify_file_after_sign_fails() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "hello world").unwrap();

    let etch_exe = env!("CARGO_BIN_EXE_etch");
    let home_dir = tempdir().unwrap();

    // 1. Sign
    let id_path = home_dir.path().join("id.json");
    Command::new(&etch_exe).arg("init")
        .env("ETCH_IDENTITY_PATH", &id_path)
        .output().unwrap();
    Command::new(&etch_exe).arg("sign")
        .arg(&file_path)
        .arg("--force")
        .arg("--name")
        .arg("Test Name")
        .arg("--project")
        .arg("Test Project")
        .arg("--domain")
        .arg("Test Domain")
        .env("ETCH_IDENTITY_PATH", &id_path)
        .output().unwrap();

    // 2. Modify file
    fs::write(&file_path, "tampered content").unwrap();

    // 3. Verify
    let output = Command::new(&etch_exe)
        .arg("verify")
        .arg(&file_path)
        .env("ETCH_IDENTITY_PATH", &id_path)
        .output()
        .expect("failed to execute verify");
    
    // Should exit with non-zero
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AUTHORSHIP VERIFIED  ✗"));
    assert!(stdout.contains("artifact_binding"));
    assert!(stdout.contains("FAILED"));
}

#[test]
fn test_sequential_signing_two_identities() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "content").unwrap();

    let etch_exe = env!("CARGO_BIN_EXE_etch");
    let home_dir = tempdir().unwrap();

    // 1. First identity signs
    let id1_path = home_dir.path().join("id1.json");
    Command::new(&etch_exe).arg("init")
        .env("ETCH_IDENTITY_PATH", &id1_path)
        .output().unwrap();
    let out1 = Command::new(&etch_exe).arg("whoami")
        .env("ETCH_IDENTITY_PATH", &id1_path)
        .output().unwrap();
    let pub1 = String::from_utf8_lossy(&out1.stdout);

    Command::new(&etch_exe).arg("sign")
        .arg(&file_path)
        .arg("--force")
        .arg("--name")
        .arg("Test Name")
        .arg("--project")
        .arg("Test Project")
        .arg("--domain")
        .arg("Test Domain")
        .env("ETCH_IDENTITY_PATH", &id1_path)
        .output().unwrap();

    // 2. Second identity signs (re-init)
    let id2_path = home_dir.path().join("id2.json");
    Command::new(&etch_exe).arg("init")
        .env("ETCH_IDENTITY_PATH", &id2_path)
        .output().unwrap();
    let out2 = Command::new(&etch_exe).arg("whoami")
        .env("ETCH_IDENTITY_PATH", &id2_path)
        .output().unwrap();
    let pub2 = String::from_utf8_lossy(&out2.stdout);
    assert_ne!(pub1, pub2);

    Command::new(&etch_exe).arg("sign")
        .arg(&file_path)
        .arg("--force")
        .arg("--name")
        .arg("Test Name")
        .arg("--project")
        .arg("Test Project")
        .arg("--domain")
        .arg("Test Domain")
        .env("ETCH_IDENTITY_PATH", &id2_path)
        .output().unwrap();

    // 3. Verify
    let output = Command::new(&etch_exe)
        .arg("verify")
        .arg(&file_path)
        .env("ETCH_IDENTITY_PATH", &id2_path)
        .output()
        .unwrap();
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("AUTHORSHIP VERIFIED  ✓"));
}
