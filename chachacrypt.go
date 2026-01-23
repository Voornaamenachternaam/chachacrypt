// [Previous code remains identical until line 704]

// setSecurePermissions sets platform-appropriate secure permissions.
func setSecurePermissions(path string) error {
	if runtime.GOOS == "windows" {
		// On Windows, remove inherited ACEs from the DACL to ensure only explicit permissions.
		var tok windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
			return fmt.Errorf("failed to open process token: %w", err)
		}
		defer tok.Close()

		tu, err := tok.GetTokenUser()
		if err != nil {
			return fmt.Errorf("failed to get token user: %w", err)
		}
		if tu == nil || tu.User == nil || tu.User.Sid == nil {
			return errors.New("failed to get current user SID")
		}
		sid := tu.User.Sid

		ea := windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}

		var dacl *windows.ACL
		if err := windows.SetEntriesInAcl(1, &ea, nil, &dacl); err != nil {
			return fmt.Errorf("failed to build DACL: %w", err)
		}
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(dacl)))

		if err := windows.SetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil,
			dacl, nil,
		); err != nil {
			return fmt.Errorf("failed to apply secure DACL: %w", err)
		}
	} else {
		// On Unix-like systems, ensure 0600.
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != secureFilePerms {
			if err := os.Chmod(path, secureFilePerms); err != nil {
				return fmt.Errorf("failed to set secure permissions: %w", err)
			}
		}
	}
	return nil
}

// [Remaining code remains identical]
