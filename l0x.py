import os
import secrets
import string
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init()

# Enhanced ASCII Art Banner for l0x
BANNER = r"""

.____      _______    ____  ___
|    |     \   _  \   \   \/  /
|    |     /  /_\  \   \     / 
|    |___  \  \_/   \  /     \ 
|_______ \  \_____  / /___/\  \
        \/        \/        \_/

       Advanced File Encryption Tool
       Coded by p0llux - v1.0
"""

def generate_password(length=16):
    """Generate a strong random password."""
    all_chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(all_chars) for _ in range(length))

def secure_wipe(file_path, passes=3):
    """Securely wipe a file by overwriting it with zeros multiple times before deletion."""
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            os.remove(file_path)
            return
        with open(file_path, 'rb+') as f:
            zero_chunk = b'\x00' * min(65536, file_size)
            for _ in range(passes):
                f.seek(0)
                bytes_written = 0
                while bytes_written < file_size:
                    chunk_size = min(65536, file_size - bytes_written)
                    f.write(zero_chunk[:chunk_size])
                    bytes_written += chunk_size
                f.flush()
                os.fsync(f.fileno())
        os.remove(file_path)
    except Exception as e:
        print(f"{Fore.RED} [!] Warning: Failed to securely wipe {file_path}: {str(e)}{Style.RESET_ALL}")
        try:
            os.remove(file_path)
        except OSError:
            pass

def encrypt_file(input_file, output_file, password, wipe_passes=3):
    """Encrypt a file using AES-256-GCM, store the extension, and wipe the original."""
    if not password:
        raise ValueError("Password cannot be empty")
    file_size = os.path.getsize(input_file)
    print(f"{Fore.GREEN} [i] File size: {file_size / 1024:.2f} KB{Style.RESET_ALL}")
    _, ext = os.path.splitext(input_file)
    ext_bytes = ext.encode('utf-8')
    ext_length = len(ext_bytes).to_bytes(1, 'big')
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(iv)
        f_out.write(ext_length)
        f_out.write(ext_bytes)
        total_bytes = file_size
        processed_bytes = 0
        while True:
            chunk = f_in.read(65536)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            f_out.write(encrypted_chunk)
            processed_bytes += len(chunk)
            print(f"\r{Fore.GREEN} [i] Encrypting: {processed_bytes / total_bytes * 100:.1f}%{Style.RESET_ALL}", end="")
        encryptor.finalize()
        f_out.write(encryptor.tag)
    print(f"\r{Fore.GREEN} [i] Encrypting: 100% Complete{Style.RESET_ALL}")
    secure_wipe(input_file, passes=wipe_passes)
    print(f"{Fore.GREEN} [+] File encrypted: {output_file}{Style.RESET_ALL}")
    print(f"{Fore.GREEN} [-] Original wiped: {input_file}{Style.RESET_ALL}")

def decrypt_file(input_file, output_file_base, password, wipe_passes=3):
    """Decrypt a file, restore the extension, and wipe the encrypted file."""
    if not password:
        raise ValueError("Password cannot be empty")
    total_size = os.path.getsize(input_file)
    print(f"{Fore.GREEN} [i] File size: {total_size / 1024:.2f} KB{Style.RESET_ALL}")
    if total_size < 45:
        raise ValueError("Invalid encrypted file: too small")
    with open(input_file, 'rb') as f_in:
        salt = f_in.read(16)
        iv = f_in.read(12)
        ext_length = int.from_bytes(f_in.read(1), 'big')
        ext = f_in.read(ext_length).decode('utf-8')
        metadata_size = 16 + 12 + 1 + ext_length
        ciphertext_length = total_size - metadata_size - 16
        f_in.seek(total_size - 16)
        tag = f_in.read(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        output_file = output_file_base + ext
        with open(output_file, 'wb') as f_out:
            f_in.seek(metadata_size)
            bytes_read = 0
            while bytes_read < ciphertext_length:
                chunk_size = min(65536, ciphertext_length - bytes_read)
                chunk = f_in.read(chunk_size)
                decrypted_chunk = decryptor.update(chunk)
                f_out.write(decrypted_chunk)
                bytes_read += chunk_size
                print(f"\r{Fore.GREEN} [i] Decrypting: {bytes_read / ciphertext_length * 100:.1f}%{Style.RESET_ALL}", end="")
            try:
                decryptor.finalize()
            except InvalidTag:
                os.remove(output_file)
                raise ValueError("Decryption failed: incorrect password or corrupted file")
    print(f"\r{Fore.GREEN} [i] Decrypting: 100% Complete{Style.RESET_ALL}")
    secure_wipe(input_file, passes=wipe_passes)
    print(f"{Fore.GREEN} [+] File decrypted: {output_file}{Style.RESET_ALL}")
    print(f"{Fore.GREEN} [-] Encrypted wiped: {input_file}{Style.RESET_ALL}")

def main():
    print(f"{Fore.GREEN}{BANNER}{Style.RESET_ALL}")
    print(f"{Fore.GREEN} Welcome to l0x - Secure your files with AES-256-GCM encryption!{Style.RESET_ALL}")
    print(f"{Fore.GREEN}=================================================================={Style.RESET_ALL}\n")
    encrypted_folder = os.path.join(os.path.dirname(__file__), "encrypted")
    os.makedirs(encrypted_folder, exist_ok=True)

    while True:
        print(f"{Fore.GREEN} [1] Encrypt a file{Style.RESET_ALL}")
        print(f"{Fore.GREEN} [2] Decrypt a file{Style.RESET_ALL}")
        print(f"{Fore.GREEN} [3] Quit{Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN}\n >> Select an option (1-3): {Style.RESET_ALL}").strip()
        if choice == '1':
            mode = 'encrypt'
            break
        elif choice == '2':
            mode = 'decrypt'
            break
        elif choice == '3':
            print(f"{Fore.GREEN}\n Goodbye from l0x!{Style.RESET_ALL}")
            return
        else:
            print(f"{Fore.RED} [!] Invalid option. Please choose 1, 2, or 3.{Style.RESET_ALL}")

    while True:
        input_file = input(f"{Fore.GREEN}\n >> Enter the path to your file: {Style.RESET_ALL}").strip()
        if os.path.isfile(input_file):
            break
        print(f"{Fore.RED} [!] File not found. Try again.{Style.RESET_ALL}")

    if mode == 'encrypt':
        prompt = f"{Fore.GREEN} >> Enter a name for the encrypted file (saved as encrypted/<name>.sc): {Style.RESET_ALL}"
    else:
        prompt = f"{Fore.GREEN} >> Enter a base name for the decrypted file (extension restored): {Style.RESET_ALL}"

    while True:
        output_name = input(prompt).strip()
        if not output_name:
            print(f"{Fore.RED} [!] Name cannot be empty.{Style.RESET_ALL}")
            continue
        if mode == 'encrypt':
            output_file = os.path.join(encrypted_folder, f"{output_name}.sc")
        else:
            output_file_base = os.path.join(encrypted_folder, output_name)
            output_file = output_file_base
        if os.path.exists(output_file):
            overwrite = input(f"{Fore.RED} [!] '{output_file}' exists. Overwrite? (y/n): {Style.RESET_ALL}").lower()
            if overwrite == 'y':
                break
            elif overwrite == 'n':
                continue
            else:
                print(f"{Fore.RED} [!] Please enter 'y' or 'n'.{Style.RESET_ALL}")
        else:
            break

    while True:
        wipe_choice = input(f"{Fore.GREEN}\n >> Perform multiple secure wipe passes? (y/n, default 3 passes): {Style.RESET_ALL}").lower()
        if wipe_choice == 'y':
            while True:
                passes = input(f"{Fore.GREEN} >> Enter number of passes (1-10): {Style.RESET_ALL}").strip()
                if passes.isdigit() and 1 <= int(passes) <= 10:
                    wipe_passes = int(passes)
                    break
                print(f"{Fore.RED} [!] Please enter a number between 1 and 10.{Style.RESET_ALL}")
            break
        elif wipe_choice == 'n' or wipe_choice == '':
            wipe_passes = 3
            break
        else:
            print(f"{Fore.RED} [!] Please enter 'y' or 'n'.{Style.RESET_ALL}")

    if mode == 'encrypt':
        while True:
            use_generated = input(f"{Fore.GREEN}\n >> Use a generated strong password? (y/n): {Style.RESET_ALL}").lower()
            if use_generated == 'y':
                password = generate_password()
                print(f"{Fore.RED}\n [+] Generated Password: {password}{Style.RESET_ALL}")
                print(f"{Fore.RED} [!] Store this securely - it’s your only key!{Style.RESET_ALL}")
                break
            elif use_generated == 'n':
                while True:
                    password1 = getpass.getpass(f"{Fore.GREEN} >> Enter your password: {Style.RESET_ALL}")
                    password2 = getpass.getpass(f"{Fore.GREEN} >> Confirm your password: {Style.RESET_ALL}")
                    if password1 == password2:
                        password = password1
                        if len(password) < 12:
                            print(f"{Fore.RED} [!] Warning: Password < 12 chars. Longer is safer.{Style.RESET_ALL}")
                        break
                    print(f"{Fore.RED} [!] Passwords don’t match. Try again.{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED} [!] Please enter 'y' or 'n'.{Style.RESET_ALL}")
    else:
        password = getpass.getpass(f"{Fore.GREEN}\n >> Enter the decryption password: {Style.RESET_ALL}")

    password_bytes = bytearray(password, 'utf-8')

    print(f"{Fore.GREEN}\n Processing...{Style.RESET_ALL}")
    try:
        if mode == 'encrypt':
            encrypt_file(input_file, output_file, password_bytes, wipe_passes)
        else:
            decrypt_file(input_file, output_file_base, password_bytes, wipe_passes)
        print(f"{Fore.GREEN}\n [✓] Operation completed successfully!{Style.RESET_ALL}")
    except ValueError as e:
        print(f"{Fore.RED} [!] Error: {str(e)}{Style.RESET_ALL}")
    except OSError as e:
        print(f"{Fore.RED} [!] Error: {str(e)}. Check permissions or disk space.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED} [!] Unexpected error: {str(e)}{Style.RESET_ALL}")
    finally:
        for _ in range(3):
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

if __name__ == "__main__":
    main()
