package chachacrypt

// ... other code ...

// Update encryptFile function
func encryptFile(...){
    // ... other code ...
    defer func() {
        if err := inFile.Close(); err != nil {
            log.Printf("Error closing input file: %v", err)
        }
    }() // Line 174
    // ... other code ...
    defer func() {
        if err := outFile.Close(); err != nil {
            log.Printf("Error closing output file: %v", err)
        }
    }() // Line 180
}

// Update decryptFile function
func decryptFile(...){
    // ... other code ...
    defer func() {
        if err := inFile.Close(); err != nil {
            log.Printf("Error closing input file: %v", err)
        }
    }() // Line 263
    // ... other code ...
    defer func() {
        if err := outFile.Close(); err != nil {
            log.Printf("Error closing output file: %v", err)
        }
    }() // Line 269
}

// ... other code ...