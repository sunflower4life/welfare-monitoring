<?php
session_start();
header("Content-Type: application/json");
include_once 'dbconnect.php';

$data = json_decode(file_get_contents("php://input"), true);

// SECURITY: CSRF Token Check
$client_token = $data['csrf_token'] ?? '';
if (!isset($_SESSION['csrf_token']) || $client_token !== $_SESSION['csrf_token']) {
    echo json_encode(["status" => "error", "message" => "Security token invalid"]);
    exit;
}

if (isset($data['user_id'], $data['amount'], $data['aid_remark'])) {
    
    // SECURITY: Numeric Validation (Item 8 in Appendix 2)
    if (!is_numeric($data['amount']) || $data['amount'] < 0) {
        echo json_encode(["status" => "error", "message" => "Invalid amount format"]);
        exit;
    }

    try {
        // SECURITY: Prepared Statement
        $stmt = $conn->prepare("INSERT INTO tbl_aid (user_id, amount, aid_remark) VALUES (?, ?, ?)");
        
        // SECURITY: Sanitization
        $remark = htmlspecialchars(strip_tags($data['aid_remark']), ENT_QUOTES, 'UTF-8');
        
        $stmt->execute([$data['user_id'], $data['amount'], $remark]);
        echo json_encode(["status" => "success"]);
    } catch (PDOException $e) {
        echo json_encode(["status" => "error", "message" => "Database error"]);
    }
}
?>