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

    // Validate aid_type (prevent invalid input and SQLi)
    $aid_type = validateInput($data['aid_type'] ?? '', 'string', 50);
    if (!in_array($aid_type, ['Food', 'Cash', 'Housing', 'Medical', 'Education'])) {
        throw new Exception("Invalid aid type");
    }

    // Validate welfare_category (prevent invalid input and SQLi)
    $welfare_category = validateInput($data['welfare_category'] ?? '', 'string', 50);
    if (!in_array($welfare_category, ['Single Mother', 'B40', 'Elderly', 'Disabled', 'Orphan'])) {
        throw new Exception("Invalid welfare category");
    }

    // Validate remarks (prevent XSS and SQLi - max 500 chars)
    $remarks = validateInput($data['remarks'] ?? '', 'string', 500);

    // Validate status
    $status = validateInput($data['status'] ?? 'Pending', 'string', 20);
    if (!in_array($status, ['Pending', 'Approved', 'Rejected', 'Completed'])) {
        throw new Exception("Invalid status");
    }

    // 3. PARAMETERIZED QUERY (SQL INJECTION PREVENTION)
    $sql = "INSERT INTO tbl_welfare (user_id, aid_type, welfare_category, remarks, status) 
            VALUES (:user_id, :aid_type, :welfare_category, :remarks, :status)";
    
    $stmt = $conn->prepare($sql);
    
    $stmt->execute([
        ':user_id' => $user_id,           // <-- SECURE: Integer
        ':aid_type' => $aid_type,         // <-- SECURE: Whitelisted
        ':welfare_category' => $welfare_category,  // <-- SECURE: Whitelisted
        ':remarks' => $remarks,           // <-- SECURE: Escaped + length limited
        ':status' => $status              // <-- SECURE: Whitelisted
    ]);

    echo json_encode(["status" => "success", "message" => "Application submitted successfully"]);

} catch (Exception $e) {
    echo json_encode(["status" => "error", "message" => $e->getMessage()]);
}
?>