#!/usr/bin/env python3
import requests
import time
import argparse
import sqlite3
from tqdm import tqdm

API_KEY = '<YOUR API KEY>'
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
VT_GUI_URL = "https://www.virustotal.com/gui/file/"
DB_FILENAME = "vt_results.db"

def create_db(db_path=DB_FILENAME):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS vt_results (
                    hash TEXT PRIMARY KEY,
                    link TEXT,
                    file_name TEXT,
                    file_type TEXT,
                    undetected INTEGER,
                    suspicious INTEGER,
                    malicious INTEGER,
                    threat_label TEXT,
                    tags TEXT
                    )''')
    conn.commit()
    return conn

def get_record_from_db(conn, hashn):
    cur = conn.cursor()
    cur.execute("SELECT hash, link, file_name, file_type, undetected, suspicious, malicious, threat_label, tags FROM vt_results WHERE hash = ?", (hashn,))
    row = cur.fetchone()
    return row

def insert_or_update_record(conn, hashn, link, file_name, file_type, undetected, suspicious, malicious, threat_label, tags):
    cur = conn.cursor()
    cur.execute('''INSERT OR REPLACE INTO vt_results (hash, link, file_name, file_type, undetected, suspicious, malicious, threat_label, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                (hashn, link, file_name, file_type, undetected, suspicious, malicious, threat_label, tags))
    conn.commit()

def main():
    parser = argparse.ArgumentParser(
        description="VirusTotal Bulk Hash Checker using VT API v3 dengan SQLite caching untuk semua hasil"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="File input yang berisi daftar hash (satu per baris)")
    parser.add_argument("-o", "--output", required=True,
                        help="File output CSV untuk menyimpan hasil analisis")
    parser.add_argument("-ns", "--no-sqlite", action="store_true",
                        help="Langsung query ke VT tanpa mengecek SQLite, tapi simpan hasil terbaru ke SQLite")
    args = parser.parse_args()
    
    # Membaca file input dan melakukan deduplikasi hash
    unique_hashes = []
    seen = set()
    with open(args.input, 'r') as f_in:
        for line in f_in:
            hashn = line.strip()
            if not hashn:
                continue
            if hashn not in seen:
                seen.add(hashn)
                unique_hashes.append(hashn)
    
    conn = create_db()
    
    with open(args.output, 'w') as f_out:
        header = "Link,File Name,File Type,Undetected,Detected_Suspicious,Detected_Malicious,Threat Label,Tags\n"
        f_out.write(header)
        
        for hashn in tqdm(unique_hashes, desc="Processing hashes", unit="hash"):
            record = None
            # Cek terlebih dahulu di SQLite jika flag -ns tidak diberikan
            if not args.no_sqlite:
                record = get_record_from_db(conn, hashn)
            
            if record:
                # Jika sudah ada di database, gunakan hasil yang tersimpan
                csv_line = f"{record[1]},{record[2]},{record[3]},{record[4]},{record[5]},{record[6]},{record[7]},{record[8]}\n"
                f_out.write(csv_line)
            else:
                headers_req = {
                    "accept": "application/json",
                    "x-apikey": API_KEY
                }
                try:
                    response = requests.get(VT_API_URL + hashn, headers=headers_req, timeout=120)
                except requests.RequestException as e:
                    error_msg = f"Error: {e}"
                    f_out.write(f"{VT_GUI_URL}{hashn},{error_msg}\n")
                    continue
                    
                if response.status_code == 404:
                    result_line = f"{VT_GUI_URL}{hashn},Not Found in Virus Total Database\n"
                    f_out.write(result_line)
                    # Simpan ke SQLite juga sebagai cache
                    insert_or_update_record(conn, hashn, VT_GUI_URL + hashn, "Not Found", "N/A", 0, 0, 0, "N/A", "N/A")
                elif response.status_code == 200:
                    result = response.json()
                    file_name = result['data']['attributes'].get('names', ["Unknown"])[0]
                    file_type = result['data']['attributes'].get('type_description', "Unknown")
                    analysis_stats = result['data']['attributes'].get('last_analysis_stats', {})
                    undetected = analysis_stats.get('undetected', 0)
                    suspicious = analysis_stats.get('suspicious', 0)
                    malicious = analysis_stats.get('malicious', 0)
                    threat_label = result['data']['attributes'].get('popular_threat_classification', {})\
                                    .get('suggested_threat_label', "None")
                    tags = result['data']['attributes'].get('tags', [])
                    tags_str = ";".join(tags) if isinstance(tags, list) else str(tags)
                    vt_link = f"{VT_GUI_URL}{hashn}"
                    csv_line = f"{vt_link},{file_name},{file_type},{undetected},{suspicious},{malicious},{threat_label},{tags_str}\n"
                    f_out.write(csv_line)
                    # Simpan atau update hasil ke SQLite (untuk semua hasil)
                    insert_or_update_record(conn, hashn, vt_link, file_name, file_type,
                                              undetected, suspicious, malicious, threat_label, tags_str)
                else:
                    f_out.write(f"{VT_GUI_URL}{hashn},Unexpected status code: {response.status_code}\n")
                
                # Delay 20 detik untuk menjaga batas rate API
                time.sleep(20)
    
    conn.close()

if __name__ == "__main__":
    main()
