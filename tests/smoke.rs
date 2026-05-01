#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_boot::repository_name(), "alani-boot");
    assert!(!alani_boot::module_names().is_empty());
}
