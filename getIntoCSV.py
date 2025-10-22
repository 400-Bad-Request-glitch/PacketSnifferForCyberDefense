import sqlite3
import pandas as pd
from tkinter import Tk, Scrollbar, RIGHT, Y, LEFT, BOTH, messagebox
from tkinter import ttk

# Connect to DB and read data
conn = sqlite3.connect("network_packets.db")
df = pd.read_sql_query("SELECT * FROM packets", conn)
conn.close()

# --- Export to CSV ---
csv_file = "network_packets_export.csv"
df.to_csv(csv_file, index=False)
print(f" Data exported to {csv_file}")

# Optionally show popup
messagebox.showinfo("Export Successful", f"Data saved to:\n{csv_file}")

# Create Tkinter window
root = Tk()
root.title("Network Packets")

# Create Treeview
tree = ttk.Treeview(root)
tree.pack(side=LEFT, fill=BOTH, expand=True)

# Add scrollbars
scroll_y = Scrollbar(root, orient="vertical", command=tree.yview)
scroll_y.pack(side=RIGHT, fill=Y)
tree.configure(yscrollcommand=scroll_y.set)

# Define columns
tree["columns"] = list(df.columns)
tree["show"] = "headings"

for col in df.columns:
    tree.heading(col, text=col)
    tree.column(col, width=200, anchor='center')

# Insert data
for _, row in df.iterrows():
    tree.insert("", "end", values=list(row))

root.mainloop()
