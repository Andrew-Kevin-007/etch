use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_end_to_end_sign_verify() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "hello world").unwrap();

    let etch_exe = env!("CARGO_BIN_EXE_etch");

    // 1. Init identity
    let output = Command::new(&etch_exe)
        .arg("init")
        .output()
        .expect("failed to execute init");
    assert!(output.status.success());

    // 2. Sign file
    let output = Command::new(&etch_exe)
        .arg("sign")
        .arg("--path")
        .arg(&file_path)
        .output()
        .expect("failed to execute sign");
    assert!(output.status.success());
    assert!(file_path.with_extension("txt.etch").exists());

    // 3. Verify file
    let output = Command::new(&etch_exe)
        .arg("verify")
        .arg("--path")
        .arg(&file_path)
        .output()
        .expect("failed to execute verify");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Verdict: PASS"));
}

#[test]
fn test_modify_file_after_sign_fails() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "hello world").unwrap();

    let etch_exe = env!("CARGO_BIN_EXE_etch");

    // 1. Sign
    Command::new(&etch_exe).arg("init").output().unwrap();
    Command::new(&etch_exe).arg("sign").arg("--path").arg(&file_path).output().unwrap();

    // 2. Modify file
    fs::write(&file_path, "tampered content").unwrap();

    // 3. Verify
    let output = Command::new(&etch_exe)
        .arg("verify")
        .arg("--path")
        .arg(&file_path)
        .output()
        .expect("failed to execute verify");
    
    // Should exit with non-zero
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Verdict: FAIL"));
    assert!(stdout.contains("artifact_binding"));
}

#[test]
fn test_sequential_signing_two_identities() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "content").unwrap();

    let etch_exe = env!("CARGO_BIN_EXE_etch");

    // We need to simulate two identities. Since identity is stored in ~/.etch,
    // we might need to override the home directory or manually move identity files.
    // For a cleaner test, we can use the library directly if we had a way to specify identity path,
    // but the CLI is wired to ~/.etch.
    // However, `etch init` overwrites.
    
    // 1. First identity signs
    Command::new(&etch_exe).arg("init").output().unwrap();
    let out1 = Command::new(&etch_exe).arg("whoami").output().unwrap();
    let pub1 = String::from_utf8_lossy(&out1.stdout);

    Command::new(&etch_exe).arg("sign").arg("--path").arg(&file_path).output().unwrap();

    // 2. Second identity signs (re-init)
    Command::new(&etch_exe).arg("init").output().unwrap();
    let out2 = Command::new(&etch_exe).arg("whoami").output().unwrap();
    let pub2 = String::from_utf8_lossy(&out2.stdout);
    assert_ne!(pub1, pub2);

    Command::new(&etch_exe).arg("sign").arg("--path").arg(&file_path).output().unwrap();

    // 3. Verify
    let output = Command::new(&etch_exe)
        .arg("verify")
        .arg("--path")
        .arg(&file_path)
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Verdict: PASS"));
    assert!(stdout.contains("Verified through entry index: 1"));
}
