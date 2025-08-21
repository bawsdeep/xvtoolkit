import sys
import io
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit
)
from xv2tool import main as ps4_main  # PS4 encrypt/decrypt
from xv2_ps4topc import process_file as ps4pc_process_file
from xv2savetool_switch import main as switch_main  # Switch/Xbox encrypt/decrypt


class Xeno2GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Xenoverse 2 Toolkit")
        self.setGeometry(100, 100, 650, 450)

        self.file_path = None
        self.is_decrypted = False

        main_layout = QVBoxLayout()

        # File label
        self.label = QLabel("No file selected")
        main_layout.addWidget(self.label)

        # File selection button
        self.select_button = QPushButton("Select File")
        self.select_button.clicked.connect(self.select_file)
        main_layout.addWidget(self.select_button)

        # Horizontal layout for main buttons
        btn_layout = QHBoxLayout()

        # PS4 encrypt/decrypt
        self.ps4_decrypt_button = QPushButton("Decrypt/Encrypt PS4")
        self.ps4_decrypt_button.clicked.connect(lambda: self._process_generic(ps4_main, "PS4"))
        self.ps4_decrypt_button.setEnabled(False)
        btn_layout.addWidget(self.ps4_decrypt_button)

        # PS4 → PC conversion
        self.ps4pc_button = QPushButton("PS4 → PC")
        self.ps4pc_button.clicked.connect(self.process_ps4pc_file)
        self.ps4pc_button.setEnabled(False)
        btn_layout.addWidget(self.ps4pc_button)

        # Switch/Xbox encrypt/decrypt
        self.switchxbox_button = QPushButton("Decrypt/Encrypt Switch/Xbox")
        self.switchxbox_button.clicked.connect(lambda: self._process_generic(switch_main, "Switch/Xbox"))
        self.switchxbox_button.setEnabled(False)
        btn_layout.addWidget(self.switchxbox_button)

        main_layout.addLayout(btn_layout)

        # Log box
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        main_layout.addWidget(self.log_box)

        self.setLayout(main_layout)
        self.apply_dark_theme()

    def apply_dark_theme(self):
        dark_style = """
        QWidget {
            background-color: #2b2b2b;
            color: #f0f0f0;
            font-family: Consolas, Courier, monospace;
            font-size: 12pt;
        }
        QPushButton {
            background-color: #3c3f41;
            border: 1px solid #5c5c5c;
            padding: 6px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #505357;
        }
        QTextEdit {
            background-color: #1e1e1e;
            color: #f0f0f0;
            border: 1px solid #5c5c5c;
        }
        QLabel {
            font-weight: bold;
        }
        """
        self.setStyleSheet(dark_style)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Save File")
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Selected: {file_path}")
            self.ps4_decrypt_button.setEnabled(True)
            self.ps4pc_button.setEnabled(True)
            self.switchxbox_button.setEnabled(True)

            # Check if file is decrypted by header
            try:
                with open(file_path, "rb") as f:
                    header = f.read(4)
                expected_header = bytes.fromhex("23 53 41 56")  # "#SAV"
                self.is_decrypted = header == expected_header
            except Exception:
                self.is_decrypted = False

    def _process_generic(self, func, platform_name):
        """Unified encrypt/decrypt handling for PS4 and Switch/Xbox"""
        if not self.file_path:
            return
        self.log_box.clear()

        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        try:
            output_path = func(self.file_path)  # assume func returns output path
            if output_path:
                self.file_path = output_path
                self.label.setText(f"Wrote: {output_path}")
        except Exception as e:
            print(f"Error ({platform_name}): {e}")

        sys.stdout = old_stdout
        self.log_box.setPlainText(buffer.getvalue())

    def process_ps4pc_file(self):
        """PS4 → PC conversion logic"""
        if not self.file_path:
            return
        self.log_box.clear()

        try:
            result = ps4pc_process_file(self.file_path, mode="auto")
            log = (
                f"{result['chosen']} → {result['output_path'].split('/')[-1]}\n"
                f"Input  SHA1: {result['input_sha1']}\n"
                f"Output SHA1: {result['output_sha1']}\n"
            )
            self.file_path = result['output_path']
            self.label.setText(f"Wrote: {result['output_path']}")
            self.log_box.setPlainText(log)
        except Exception as e:
            self.log_box.setPlainText(f"Error: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Xeno2GUI()
    window.show()
    sys.exit(app.exec())
