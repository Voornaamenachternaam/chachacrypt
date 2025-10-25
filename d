[1mdiff --git a/chachacrypt.go b/chachacrypt.go[m
[1mindex 06fda95..ec9d13e 100644[m
[1m--- a/chachacrypt.go[m
[1m+++ b/chachacrypt.go[m
[36m@@ -272,10 +272,10 @@[m [mfunc generatePassword(n int) (string, error) {[m
 [m
 func encryptFile(inputFile, outputFile string, password []byte, cfg config) error {[m
 	if err := validateFilePath(inputFile); err != nil {[m
[31m-		return fmt.Errorf("invalid input path")[m
[32m+[m		[32mreturn errors.New("invalid input path")[m
 	}[m
 	if err := validateFilePath(outputFile); err != nil {[m
[31m-		return fmt.Errorf("invalid output path")[m
[32m+[m		[32mreturn errors.New("invalid output path")[m
 	}[m
 [m
 	// Use os.Create so default OS behavior is applied (cross-platform)[m
[36m@@ -374,7 +374,7 @@[m [mfunc encryptFile(inputFile, outputFile string, password []byte, cfg config) erro[m
 			if _, err := outFile.Write(nonce); err != nil {[m
 				return fmt.Errorf("error writing nonce: %w", err)[m
 			}[m
[31m-			var clen uint32 = uint32(len(ct))[m
[32m+[m			[32mvar clen = uint32(len(ct))[m
 			if err := binary.Write(outFile, binary.LittleEndian, clen); err != nil {[m
 				return fmt.Errorf("error writing ciphertext length: %w", err)[m
 			}[m
[36m@@ -400,10 +400,10 @@[m [mfunc encryptFile(inputFile, outputFile string, password []byte, cfg config) erro[m
 [m
 func decryptFile(inputFile, outputFile string, password []byte, cfg config) error {[m
 	if err := validateFilePath(inputFile); err != nil {[m
[31m-		return fmt.Errorf("invalid input path")[m
[32m+[m		[32mreturn errors.New("invalid input path")[m
 	}[m
 	if err := validateFilePath(outputFile); err != nil {[m
[31m-		return fmt.Errorf("invalid output path")[m
[32m+[m		[32mreturn errors.New("invalid output path")[m
 	}[m
 [m
 	inFile, err := os.Open(inputFile)[m
[36m@@ -417,12 +417,12 @@[m [mfunc decryptFile(inputFile, outputFile string, password []byte, cfg config) erro[m
 		return fmt.Errorf("failed to read header: %w", err)[m
 	}[m
 	if string(header.Magic[:8]) != MagicNumber || header.Magic[8] != FileVersion {[m
[31m-		return fmt.Errorf("invalid file format or unsupported version")[m
[32m+[m		[32mreturn errors.New("invalid file format or unsupported version")[m
 	}[m
 [m
 	saltSize := int(header.SaltSize)[m
 	if saltSize <= 0 || saltSize > 1024 {[m
[31m-		return fmt.Errorf("invalid salt size")[m
[32m+[m		[32mreturn errors.New("invalid salt size")[m
 	}[m
 	salt := make([]byte, saltSize)[m
 	if _, err := io.ReadFull(inFile, salt); err != nil {[m
[36m@@ -447,12 +447,12 @@[m [mfunc decryptFile(inputFile, outputFile string, password []byte, cfg config) erro[m
 [m
 	nonceSize := int(header.NonceSize)[m
 	if nonceSize != aead.NonceSize() {[m
[31m-		return fmt.Errorf("invalid file format or unsupported version")[m
[32m+[m		[32mreturn errors.New("invalid file format or unsupported version")[m
 	}[m
 [m
 	baseHeaderBuf := new(bytes.Buffer)[m
 	if err := binary.Write(baseHeaderBuf, binary.LittleEndian, header); err != nil {[m
[31m-		return fmt.Errorf("internal error")[m
[32m+[m		[32mreturn errors.New("internal error")[m
 	}[m
 	baseAAD := baseHeaderBuf.Bytes()[m
 [m
[36m@@ -462,19 +462,19 @@[m [mfunc decryptFile(inputFile, outputFile string, password []byte, cfg config) erro[m
 		if _, err := io.ReadFull(inFile, nonce); err == io.EOF {[m
 			break[m
 		} else if err != nil {[m
[31m-			return fmt.Errorf("error reading nonce or reached unexpected EOF")[m
[32m+[m			[32mreturn errors.New("error reading nonce or reached unexpected EOF")[m
 		}[m
 [m
 		var clen uint32[m
 		if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {[m
[31m-			return fmt.Errorf("error reading ciphertext length")[m
[32m+[m			[32mreturn errors.New("error reading ciphertext length")[m
 		}[m
 		if clen > (1 << 30) {[m
[31m-			return fmt.Errorf("invalid ciphertext length")[m
[32m+[m			[32mreturn errors.New("invalid ciphertext length")[m
 		}[m
 		ct := make([]byte, clen)[m
 		if _, err := io.ReadFull(inFile, ct); err != nil {[m
[31m-			return fmt.Errorf("error reading ciphertext")[m
[32m+[m			[32mreturn errors.New("error reading ciphertext")[m
 		}[m
 [m
 		var aad bytes.Buffer[m
[36m@@ -486,12 +486,12 @@[m [mfunc decryptFile(inputFile, outputFile string, password []byte, cfg config) erro[m
 		plain, err := aead.Open(nil, nonce, ct, aad.Bytes())[m
 		zeroBytes(ct)[m
 		if err != nil {[m
[31m-			return fmt.Errorf("decryption failed or file is corrupted")[m
[32m+[m			[32mreturn errors.New("decryption failed or file is corrupted")[m
 		}[m
 [m
 		if _, err := outFile.Write(plain); err != nil {[m
 			zeroBytes(plain)[m
[31m-			return fmt.Errorf("failed to write plaintext")[m
[32m+[m			[32mreturn errors.New("failed to write plaintext")[m
 		}[m
 		zeroBytes(plain)[m
 [m
