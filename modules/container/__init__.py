"""Container domain PRO v7.0."""
from .image_scanner import ContainerScanner

__all__ = ["ContainerScanner"]

def analyze_container(file_path: str = None, directory: str = None) -> dict:
    scanner = ContainerScanner()
    if directory:
        return scanner.scan_directory(directory)
    if file_path:
        if file_path.endswith(".tar") or "image" in file_path:
            return scanner.scan_image_tar(file_path)
        else:
            return scanner.scan_dockerfile(file_path)
    return {"status": "error", "error": "file_path or directory required"}
