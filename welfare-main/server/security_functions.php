<?php
/**
 * This file contains all reusable security validation functions
 */

// 1. INPUT VALIDATION - Prevents invalid/unexpected input
function validateInput($input, $type = 'string', $maxLength = null) {
    // Remove leading/trailing whitespace
    $input = trim($input);
    
    // Prevent excessively long strings (prevents buffer overflow)
    if ($maxLength && strlen($input) > $maxLength) {
        throw new Exception("Input exceeds maximum length of $maxLength characters");
    }
    
    switch ($type) {
        case 'email':
            if (!filter_var($input, FILTER_VALIDATE_EMAIL)) {
                throw new Exception("Invalid email format");
            }
            return filter_var($input, FILTER_SANITIZE_EMAIL);
            
        case 'numeric':
            if (!is_numeric($input)) {
                throw new Exception("Input must be numeric");
            }
            return (float)$input;
            
        case 'integer':
            if (!ctype_digit((string)$input) && intval($input) != $input) {
                throw new Exception("Input must be an integer");
            }
            return (int)$input;
            
        case 'string':
            // IMPORTANT: Escape HTML characters FIRST, THEN return
            // This converts < > " ' & to HTML entities
            $escaped = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
            return $escaped;
            
        case 'phone':
            // Allow only digits, +, -, and spaces
            if (!preg_match('/^[0-9\+\-\s]{10,15}$/', $input)) {
                throw new Exception("Invalid phone format");
            }
            return $input;
            
        default:
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
}

// 2. OUTPUT ESCAPING - For displaying data safely
function escapeOutput($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

// 3. CSRF TOKEN GENERATION
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// 4. CSRF TOKEN VERIFICATION
function verifyCSRFToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

// 5. FILE UPLOAD VALIDATION
function validateFileUpload($file, $allowedTypes = ['jpg', 'jpeg', 'png', 'pdf'], $maxSize = 5242880) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        throw new Exception("File upload error");
    }
    
    // Check file size
    if ($file['size'] > $maxSize) {
        throw new Exception("File size exceeds maximum limit");
    }
    
    // Validate file extension
    $fileExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($fileExt, $allowedTypes)) {
        throw new Exception("File type not allowed");
    }
    
    // Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'pdf' => 'application/pdf'
    ];
    
    if ($mimeType !== $allowedMimes[$fileExt]) {
        throw new Exception("Invalid file type");
    }
    
    return true;
}

// 6. PATH TRAVERSAL PREVENTION
function validateFilePath($path) {
    $realPath = realpath($path);
    $baseDir = realpath(__DIR__ . '/uploads');
    
    if (!$realPath || strpos($realPath, $baseDir) !== 0) {
        throw new Exception("Invalid file path");
    }
    
    return $realPath;
}

?>