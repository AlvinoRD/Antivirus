import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import re
from datetime import datetime
import shutil

# Fungsi untuk menghitung checksum MD5 dari file
def calculate_checksum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Fungsi untuk memuat database virus dari TXT
def load_virus_database():
    virus_db_file = 'virus_database.txt'
    if os.path.exists(virus_db_file):
        with open(virus_db_file, 'r') as f:
            return [line.strip() for line in f]
    else:
        return []

# Fungsi untuk mencatat log aktivitas
def log_activity(activity):
    with open("antivirus_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {activity}\n")

# Fungsi untuk mengarantina file
def quarantine_file(file_path):
    quarantine_dir = "./quarantine/"
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    quarantined_path = quarantine_dir + os.path.basename(file_path) + ".quar"
    shutil.move(file_path, quarantined_path)
    messagebox.showinfo("File Quarantined", f"File moved to quarantine: {quarantined_path}")
    log_activity(f"File quarantined: {file_path}")

# Fungsi untuk menghapus file
def delete_file(file_path):
    os.remove(file_path)
    messagebox.showinfo("File Deleted", f"File {file_path} has been deleted.")
    log_activity(f"File deleted: {file_path}")

# Fungsi untuk mengecek varian virus berdasarkan nama dan nomor dasar
def is_variant(file_name, virus_files):
    for virus_file in virus_files:
        # Ekstrak bagian dasar nama file (tanpa ekstensi dan varian tambahan)
        base_pattern = re.match(r"(.+?)(\d+)([a-zA-Z]*)\.\w+$", virus_file)
        if base_pattern:
            base_name, number, _ = base_pattern.groups()
            # Cek apakah file baru adalah varian dari file dasar di database
            variant_pattern = rf"{re.escape(base_name)}{number}[a-zA-Z]*\.\w+$"
            if re.match(variant_pattern, file_name):
                return True
    return False

# Fungsi untuk mengecek apakah file terinfeksi virus
def check_file(file_path):
    file_name = os.path.basename(file_path)
    file_checksum = calculate_checksum(file_path)
    virus_db = load_virus_database()

    # Pisahkan database menjadi checksum dan nama file virus
    known_checksums = [line for line in virus_db if len(line) == 32]
    known_virus_files = [line for line in virus_db if len(line) != 32]

    if file_checksum in known_checksums:
        result = messagebox.askyesno("Virus Detected", "Virus detected! Quarantine or Delete?")
        if result:
            quarantine_file(file_path)
        else:
            delete_file(file_path)
    elif is_variant(file_name, known_virus_files):
        messagebox.showwarning("Potential Variant Detected", "This file is a variant of an existing virus.")
        quarantine_file(file_path)
    else:
        messagebox.showinfo("No Virus Detected", "This file is clean.")
        log_activity(f"File checked: {file_path} - Clean")

# Fungsi untuk membuka dialog dan mengunggah file (termasuk file .py)
def upload_file():
    file_path = filedialog.askopenfilename(
        title="Select File",
        filetypes=[("Supported Files", "*.txt *.docx *.pptx *.xls *.xlsx *.py *.bat")]  # Tambahkan *.py
    )
    if file_path:
        check_file(file_path)

# Fungsi untuk menambahkan checksum dan nama file ke database virus (termasuk file .py)
def add_to_virus_database():
    file_path = filedialog.askopenfilename(
        title="Select File to Add to Virus Database",
        filetypes=[("Supported Files", "*.txt *.docx *.pptx *.xls *.xlsx *.py *.bat")]  # Tambahkan *.py
    )
    if file_path:
        file_checksum = calculate_checksum(file_path)
        file_name = os.path.basename(file_path)
        with open('virus_database.txt', 'a') as f:
            f.write(file_checksum + '\n')
            f.write(file_name + '\n')
        messagebox.showinfo("Success", "File checksum and name added to virus database.")
        log_activity(f"Checksum and file name added: {file_checksum}, {file_name}")

# Fungsi untuk keluar dari aplikasi
def exit_app():
    root.quit()

# Setup antarmuka grafis menggunakan Tkinter
root = tk.Tk()
root.title("Simple Antivirus")
root.geometry("500x400")
root.configure(bg="#f0f0f0")

# Header
header_frame = tk.Frame(root, bg="#004c99", pady=10)
header_frame.pack(fill="x")

header_label = tk.Label(
    header_frame, text="Simple Antivirus", bg="#004c99", fg="white",
    font=("Arial", 16, "bold")
)
header_label.pack()

# Konten utama
main_frame = tk.Frame(root, padx=20, pady=20, bg="#f0f0f0")
main_frame.pack(fill="both", expand=True)

description_label = tk.Label(
    main_frame, text="Upload a file to check for viruses or add it to the virus database.",
    bg="#f0f0f0", font=("Arial", 12)
)
description_label.pack(pady=10)

# Tombol untuk mengunggah file dan memeriksa virus
upload_button = tk.Button(
    main_frame, text="Upload and Check File", command=upload_file,
    width=25, height=2, bg="#007acc", fg="white", font=("Arial", 10)
)
upload_button.pack(pady=10)

# Tombol untuk menambahkan file ke database virus
add_virus_button = tk.Button(
    main_frame, text="Add File to Virus Database", command=add_to_virus_database,
    width=25, height=2, bg="#e68a00", fg="white", font=("Arial", 10)
)
add_virus_button.pack(pady=10)

# Tombol untuk keluar dari aplikasi
exit_button = tk.Button(
    main_frame, text="Exit", command=exit_app,
    width=25, height=2, bg="#d9534f", fg="white", font=("Arial", 10)
)
exit_button.pack(pady=20)

# Menjalankan aplikasi
root.mainloop()
