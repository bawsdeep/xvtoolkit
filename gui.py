import sys
import io
import os
import platform
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QTextEdit
)
from xv2tool import main as ps4_main 
from xv2_ps4topc import process_file as ps4pc_process_file


class Xeno2GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Xenoverse 2 Toolkit")
        self.setGeometry(100, 100, 650, 450)

        self.file_path = None
        self.last_dir = os.path.expanduser("~")

        main_layout = QVBoxLayout()

        btn_layout = QHBoxLayout()

        # PS4 encrypt/decrypt
        self.ps4_decrypt_button = QPushButton("Decrypt/Encrypt PS4")
        self.ps4_decrypt_button.clicked.connect(
            lambda: self._select_and_process(ps4_main, "PS4")
        )
        btn_layout.addWidget(self.ps4_decrypt_button)

        # PS4 ↔ PC conversion
        self.ps4pc_button = QPushButton("PS4 ↔ PC")
        self.ps4pc_button.clicked.connect(self.process_ps4pc_file)
        btn_layout.addWidget(self.ps4pc_button)

        # Switch/Xbox encrypt/decrypt
        self.switchxbox_button = QPushButton("Decrypt/Encrypt Switch/Xbox")
        self.switchxbox_button.clicked.connect(self.process_switchxbox)
        btn_layout.addWidget(self.switchxbox_button)

        # Ensure all buttons are same size
        self._equalize_button_sizes([
            self.ps4_decrypt_button, 
            self.ps4pc_button, 
            self.switchxbox_button
        ])

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
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #505357;
        }
        QTextEdit {
            background-color: #1e1e1e;
            color: #f0f0f0;
            border: 1px solid #5c5c5c;
        }
        """
        self.setStyleSheet(dark_style)

    def _equalize_button_sizes(self, buttons):
        """Make all buttons the same size as the largest one."""
        max_width = max(btn.sizeHint().width() for btn in buttons)
        max_height = max(btn.sizeHint().height() for btn in buttons)
        for btn in buttons:
            btn.setMinimumSize(max_width, max_height)

    def _select_file(self):
        """Open file dialog and remember last used directory."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Save File", self.last_dir
        )
        if file_path:
            self.file_path = file_path
            self.last_dir = os.path.dirname(file_path)
            return True
        return False

    def _select_and_process(self, func, platform_name):
        """Select file and run a processing function (PS4)."""
        if not self._select_file():
            return
        self.log_box.clear()

        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        try:
            output_path = func(self.file_path)
            if output_path:
                self.file_path = output_path
        except Exception as e:
            print(f"Error ({platform_name}): {e}")

        sys.stdout = old_stdout
        self.log_box.setPlainText(buffer.getvalue())

    def process_ps4pc_file(self):
        """PS4 ↔ PC conversion logic."""
        if not self._select_file():
            return
        self.log_box.clear()

        try:
            result = ps4pc_process_file(self.file_path, mode="auto")
            log = (
                f"{result['chosen']} ↔ {result['output_path'].split('/')[-1]}\n"
                f"Input  SHA1: {result['input_sha1']}\n"
                f"Output SHA1: {result['output_sha1']}\n"
            )
            self.file_path = result["output_path"]
            self.log_box.setPlainText(log)
        except Exception as e:
            self.log_box.setPlainText(f"Error: {e}")

    def process_switchxbox(self):
        """Run external Switch/Xbox binary (via Wine on Linux/macOS)."""
        if not self._select_file():
            return
        self.log_box.clear()

        exe_name = "xv2savdec_switch.exe"
        if platform.system() in ["Linux", "Darwin"]:
            cmd = ["wine", exe_name, self.file_path]
        else:
            cmd = [exe_name, self.file_path]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, cwd=self.last_dir
            )
            if result.stdout:
                self.log_box.setPlainText(result.stdout)
            if result.stderr:
                self.log_box.append(f"Errors:\n{result.stderr}")
        except Exception as e:
            self.log_box.setPlainText(f"Error running {exe_name}: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Xeno2GUI()
    window.show()
    sys.exit(app.exec())
