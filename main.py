import flet as ft
import os
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from dotenv import load_dotenv
import json


class SecureVault:
    def __init__(self):
        self.app_folder = "Secure Vault"
        self.vault_path = os.path.join(os.path.expanduser("~"), self.app_folder)
        self.config_file = os.path.join(self.vault_path, ".config")
        self.encrypted_folder = os.path.join(self.vault_path, "encrypted")
        self.setup_folders()
        self.file_locations = {}
        self.load_file_locations()

    def setup_folders(self):
        os.makedirs(self.vault_path, exist_ok=True)
        os.makedirs(self.encrypted_folder, exist_ok=True)

    def load_file_locations(self):
        try:
            with open(os.path.join(self.vault_path, "file_locations.json"), "r") as f:
                self.file_locations = json.load(f)
        except FileNotFoundError:
            self.file_locations = {}

    def save_file_locations(self):
        with open(os.path.join(self.vault_path, "file_locations.json"), "w") as f:
            json.dump(self.file_locations, f)

    def generate_key(self, password: str) -> bytes:
        salt = b'secure_vault_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def save_password_hash(self, password: str):
        key = self.generate_key(password)
        with open(self.config_file, "wb") as f:
            f.write(key)

    def verify_password(self, password: str) -> bool:
        try:
            with open(self.config_file, "rb") as f:
                stored_key = f.read()
            return stored_key == self.generate_key(password)
        except FileNotFoundError:
            return False

    def encrypt_file(self, file_path: str, password: str):
        key = self.generate_key(password)
        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            file_data = file.read()

        encrypted_data = fernet.encrypt(file_data)

        # Generate a unique filename for encrypted file
        encrypted_filename = base64.urlsafe_b64encode(os.path.basename(file_path).encode()).decode()
        encrypted_path = os.path.join(self.encrypted_folder, encrypted_filename)

        with open(encrypted_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Store original location
        self.file_locations[encrypted_filename] = {
            "original_path": file_path,
            "original_name": os.path.basename(file_path)
        }
        self.save_file_locations()

        # Remove original file
        os.remove(file_path)

        return encrypted_path

    def decrypt_file(self, encrypted_filename: str, password: str) -> str:
        key = self.generate_key(password)
        fernet = Fernet(key)

        encrypted_path = os.path.join(self.encrypted_folder, encrypted_filename)
        original_info = self.file_locations[encrypted_filename]
        original_path = original_info["original_path"]

        with open(encrypted_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        # Ensure the original directory exists
        os.makedirs(os.path.dirname(original_path), exist_ok=True)

        with open(original_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        # Remove encrypted file and its entry
        os.remove(encrypted_path)
        del self.file_locations[encrypted_filename]
        self.save_file_locations()

        return original_path


def main(page: ft.Page):
    page.title = "Secure Vault"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 400
    page.window_height = 800
    page.padding = 20

    vault = SecureVault()
    selected_files = []

    def handle_password_submit(e):
        password = password_field.value
        if not password:
            page.show_snack_bar(ft.SnackBar(content=ft.Text("Please enter a password")))
            return

        if not vault.verify_password(password):
            if os.path.exists(vault.config_file):
                page.show_snack_bar(ft.SnackBar(content=ft.Text("Incorrect password")))
                return
            else:
                vault.save_password_hash(password)

        page.session.set("password", password)
        password_dialog.open = False
        main_content.visible = True
        page.update()

    def pick_files_dialog(e):
        file_picker.pick_files(
            allow_multiple=True,
            file_type=ft.FilePickerFileType.VIDEO,
        )

    def handle_files_selected(e: ft.FilePickerResultEvent):
        if e.files:
            for file in e.files:
                if file.path not in selected_files:
                    selected_files.append(file.path)
            update_selected_files_text()

    def update_selected_files_text():
        if not selected_files:
            selected_files_text.value = "No files selected"
        else:
            selected_files_text.value = "\n".join([os.path.basename(f) for f in selected_files])
        page.update()

    def encrypt_selected_files(e):
        if not selected_files:
            page.show_snack_bar(ft.SnackBar(content=ft.Text("Please select files first")))
            return

        password = page.session.get("password")
        progress = ft.ProgressBar(width=300)
        page.add(progress)

        try:
            for file_path in selected_files:
                vault.encrypt_file(file_path, password)

            selected_files.clear()
            update_selected_files_text()
            page.show_snack_bar(ft.SnackBar(content=ft.Text("Files encrypted successfully")))
        except Exception as ex:
            page.show_snack_bar(ft.SnackBar(content=ft.Text(f"Error: {str(ex)}")))
        finally:
            page.remove(progress)
            page.update()

    def show_encrypted_files(e):
        encrypted_files_list.controls.clear()
        for filename in os.listdir(vault.encrypted_folder):
            original_name = vault.file_locations[filename]["original_name"]
            encrypted_files_list.controls.append(
                ft.Checkbox(
                    label=original_name,
                    value=False,
                    data=filename
                )
            )
        encrypted_files_dialog.open = True
        page.update()

    def decrypt_selected_files(e):
        password = page.session.get("password")
        selected = [cb for cb in encrypted_files_list.controls if cb.value]

        if not selected:
            page.show_snack_bar(ft.SnackBar(content=ft.Text("Please select files to decrypt")))
            return

        progress = ft.ProgressBar(width=300)
        page.add(progress)

        try:
            for checkbox in selected:
                vault.decrypt_file(checkbox.data, password)

            page.show_snack_bar(ft.SnackBar(content=ft.Text("Files decrypted successfully")))
            encrypted_files_dialog.open = False
        except Exception as ex:
            page.show_snack_bar(ft.SnackBar(content=ft.Text(f"Error: {str(ex)}")))
        finally:
            page.remove(progress)
            page.update()

    # Password Dialog
    password_field = ft.TextField(
        label="Enter Password",
        password=True,
        width=300,
    )

    password_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Security Check"),
        content=ft.Column(
            controls=[
                password_field,
                ft.ElevatedButton(
                    text="Submit",
                    on_click=handle_password_submit,
                    width=300,
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
    )

    # File Picker
    file_picker = ft.FilePicker(on_result=handle_files_selected)
    page.overlay.append(file_picker)

    # Selected Files Display
    selected_files_text = ft.Text("No files selected", size=12)

    # Encrypted Files Dialog
    encrypted_files_list = ft.Column(scroll=ft.ScrollMode.AUTO, height=400)

    encrypted_files_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Encrypted Files"),
        content=ft.Column(
            controls=[
                encrypted_files_list,
                ft.ElevatedButton(
                    text="Decrypt Selected",
                    on_click=decrypt_selected_files,
                    width=300,
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
    )

    # Main Content
    main_content = ft.Column(
        controls=[
            ft.Text("Secure Vault", size=30, weight=ft.FontWeight.BOLD),
            ft.ElevatedButton(
                text="Select Videos",
                on_click=pick_files_dialog,
                width=300,
                icon=ft.icons.FILE_UPLOAD,
            ),
            selected_files_text,
            ft.ElevatedButton(
                text="Encrypt Selected",
                on_click=encrypt_selected_files,
                width=300,
                icon=ft.icons.LOCK,
            ),
            ft.ElevatedButton(
                text="View Encrypted Files",
                on_click=show_encrypted_files,
                width=300,
                icon=ft.icons.FOLDER,
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=20,
    )
    main_content.visible = False

    page.add(main_content)
    page.dialog = password_dialog
    password_dialog.open = True
    page.update()


if __name__ == "__main__":
    ft.app(target=main, view=ft.AppView.FLET_APP)
