<?php
session_start();

header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");

include_once 'dbconnect.php';
include_once 'security_functions.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["status" => "error", "message" => "Invalid request method"]);
    exit;
}

try {
    // 1. AUTHENTICATION CHECK
    $user_id = $_SESSION['user_id'] ?? null;
    if (!$user_id) {
        throw new Exception("Unauthorized access");
    }

    // 2. INPUT VALIDATION
    $data = json_decode(file_get_contents("php://input"), true);

    if (!$data) {
        throw new Exception("No data received");
    }

    // Validate user_id (integer only)
    $user_id = validateInput($user_id, 'integer');

    // Validate complaint_type (prevent invalid input and SQLi)
    $complaint_type = validateInput($data['complaint_type'] ?? '', 'string', 50);
    $validTypes = ['Infrastructure', 'Welfare', 'Safety', 'Governance', 'Other'];
    if (!in_array($complaint_type, $validTypes)) {
        throw new Exception("Invalid complaint type");
    }

    // Validate complaint_details (prevent XSS and SQLi - max 1000 chars)
    $complaint_details = validateInput($data['complaint_details'] ?? '', 'string', 1000);
    if (strlen($complaint_details) < 10) {
        throw new Exception("Complaint details must be at least 10 characters");
    }

    // Validate status
    $status = validateInput($data['status'] ?? 'New', 'string', 20);
    if (!in_array($status, ['New', 'Pending', 'In Progress', 'Resolved'])) {
        throw new Exception("Invalid status");
    }

    // 3. PARAMETERIZED QUERY (SQL INJECTION PREVENTION)
    $sql = "INSERT INTO tbl_complaint (user_id, complaint_type, complaint_details, status)
            VALUES (:user_id, :complaint_type, :complaint_details, :status)";

    $stmt = $conn->prepare($sql);

    $stmt->execute([
        ':user_id' => $user_id,                    // <-- SECURE: Integer
        ':complaint_type' => $complaint_type,      // <-- SECURE: Whitelisted
        ':complaint_details' => $complaint_details,  // <-- SECURE: Escaped + length limited
        ':status' => $status                       // <-- SECURE: Whitelisted
    ]);

    echo json_encode([
        "status" => "success",
        "message" => "Complaint submitted successfully"
    ]);

} catch (Exception $e) {
    echo json_encode([
        "status" => "error",
        "message" => $e->getMessage()
    ]);
}
?>