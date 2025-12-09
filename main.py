from backup.trailer_data_parsing import SamsungSEFEditor

if __name__ == '__main__':
    # --- EXAMPLE USAGE ---
    editor = SamsungSEFEditor('/home/kfir/Desktop/scrambler/trailer_data_parser/20251127_092059.jpg')
    editor.list_entries()
    #
    # Modify Timestamp
    editor.set_entry(0xa01, "123456789123456789")

    editor.save('/home/kfir/Desktop/scrambler/jpeg_metadata_parser/new_file.jpg')

    x = SamsungSEFEditor('/home/kfir/Desktop/scrambler/trailer_data_parser/new_file.jpg').entries

    print(x)
