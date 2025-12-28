@app.route('/api/files', methods=['GET'])
@token_required
    # 需要有效的JWT token才能访问
    # ... 文件列表逻辑
def api_list_files(current_user):
    # List available files
    files = []
    files_dir = Path(app.config['UPLOAD_FOLDER'])
    if files_dir.exists():
        for file_path in files_dir.glob('*.enc'):
            files.append({
                'name': file_path.stem,  # filename without .enc extension
                'size': file_path.stat().st_size,
                'encrypted_name': file_path.name
            })
    
    return jsonify({'files': files})