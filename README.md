# l0x_crypt
File Encryption Tool By p0llux.


Key Features and Enhancements
1. Multiple Overwrites with Zeros
* Request Fulfillment: As per your request, the secure_wipe function now overwrites the file with zeros multiple times (default is 3 passes) before deletion. This ensures that the original data is extra safe and harder to recover, even with advanced forensic tools.
* Implementation: The function uses a buffer of zeros (b'\x00') and writes it over the entire file in chunks, repeating the process for the specified number of passes. os.fsync() ensures the data is physically written to disk.
* User Control: Users can choose the number of passes (1-10) or accept the default of 3, balancing security and performance.
2. Password Security
* Memory Overwrite: The password is stored in a bytearray and overwritten with zeros three times after use in the finally block. This reduces the chance of the password lingering in memory.
* Strong Password Option: Users can opt for a randomly generated 16-character password using secrets, which is cryptographically secure.
3. Encryption and Decryption
* Algorithm: Uses AES-256 in GCM mode for authenticated encryption, ensuring both confidentiality and integrity.
* File Extension: The original file extension is preserved and restored during decryption.
* Error Handling: Robust checks for file corruption, incorrect passwords, and I/O issues.
4. Extra Changes Worth Doing
* Default Wipe Passes: Set to 3 instead of 1 for extra safety, aligning with your request for "extra extra safe" wiping. Users can still adjust this.
* Improved secure_wipe Robustness: If overwriting fails (e.g., due to permissions), it falls back to a simple os.remove() to ensure the file is still deleted.
* Chunked Writing in secure_wipe: Uses a 64KB buffer for zero-overwriting, optimizing performance for large files.
* User Interface: Enhanced prompts and color-coded output (via colorama) for better readability and feedback.
* Input Validation: Stricter checks for file existence, empty names, and invalid wipe pass inputs.
5. Security Notes
* Single Pass Sufficiency: While modern SSDs and HDDs often make data unrecoverable with one overwrite due to wear leveling and low-level formatting, multiple passes (e.g., 3) provide additional assurance for users concerned about theoretical recovery risks.
* KDF Iterations: Uses 100,000 iterations of PBKDF2-SHA256 to derive the encryption key, balancing security and performance.


How to Use
1. Run the Script: Execute the Python file in a terminal.
2. Choose an Option: Select 1 (encrypt), 2 (decrypt), or 3 (quit).
3. Provide File Path: Enter the path to the file you want to process.
4. Set Output Name: Specify the name for the encrypted (.sc) or decrypted file.
5. Wipe Passes: Choose whether to adjust the number of wipe passes (default is 3).
6. Password: Opt for a generated password or enter your own (hidden input for decryption).
7. Result: The script processes the file and securely wipes the original/encrypted file.

