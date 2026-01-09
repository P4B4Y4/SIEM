#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Minimal test GUI to verify EXE works
"""
import sys
import tkinter as tk
from tkinter import messagebox

print("TEST: Starting test_gui.py")

try:
    print("TEST: Creating Tk root...")
    root = tk.Tk()
    print("TEST: Tk root created")
    
    root.title("JFS SIEM Agent - TEST")
    root.geometry("400x200")
    
    label = tk.Label(root, text="GUI is working!", font=("Arial", 14))
    label.pack(pady=20)
    
    print("TEST: Showing messagebox...")
    messagebox.showinfo("Test", "GUI is working correctly!")
    
    print("TEST: Starting mainloop...")
    root.mainloop()
    print("TEST: Mainloop ended")
    
except Exception as e:
    print(f"TEST ERROR: {e}")
    import traceback
    traceback.print_exc()
    messagebox.showerror("Error", f"Error: {e}")

print("TEST: Script ended")
