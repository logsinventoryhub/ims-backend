<?php
header("Content-type:application/json;charset=utf-8");
$data = json_decode(file_get_contents("php://input"), true);
// Allow requests from any origin (for testing/development only)
header("Access-Control-Allow-Origin: *");

// Allow specific methods
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

// Allow headers that the client might send
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Headers: X-Requested-With, content-type, access-control-allow-origin, access-control-allow-methods, access-control-allow-headers");

// Get Database credentials
$config = require __DIR__ . '/config/database.php';

// Import server api endpoint containing methods to fulfil request key task
require("logsphpbackend.php");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}


########################################################################################################################################################################################
// LOGS API SIGN UP
########################################################################################################################################################################################
if ($data["key"] === "signUp") {

    // Required Fields Check
    $requiredFields = ["businessName", "businessEmail", "businessCountry", "businessState", "businessAddress", "firstName", "lastName", "password"];
    foreach ($requiredFields as $field) {
        if (empty(trim($data[$field] ?? ''))) {
            echo json_encode([
                "code" => "000",
                "message" => "Please enter appropriate values for all required * fields!"
            ]);
            exit;
        }
    }

    // Validate Business Name (allow all characters, limit length)
    $businessName = trim($data["businessName"]);
    if (mb_strlen($businessName) > 100) {
        echo json_encode([
            "code" => "000",
            "message" => "Business Name must not exceed 100 characters."
        ]);
        exit;
    }

    // Validate Business Email
    $businessEmail = trim($data["businessEmail"]);
    if (!filter_var($businessEmail, FILTER_VALIDATE_EMAIL)) {
        echo json_encode([
            "code" => "000",
            "message" => "Please enter a valid email address."
        ]);
        exit;
    }

    // Validate Business Address (allow all characters, limit length)
    $businessAddress = trim($data["businessAddress"]);
    if (mb_strlen($businessAddress) > 250) {
        echo json_encode([
            "code" => "000",
            "message" => "Business Address must not exceed 250 characters."
        ]);
        exit;
    }

    // Validate First and Last Name (allow all characters, limit length)
    $firstName = trim($data["firstName"]);
    $lastName = trim($data["lastName"]);
    if (mb_strlen($firstName) > 50 || mb_strlen($lastName) > 50) {
        echo json_encode([
            "code" => "000",
            "message" => "First and Last Names must not exceed 50 characters each."
        ]);
        exit;
    }

    // Validate Phone Number
    if (isset($data["phoneNumber"])) {
        $phonePattern = '/^\+?\d{8,15}$/';
        if (!preg_match($phonePattern, $data["phoneNumber"])) {
            echo json_encode([
                "code" => "009",
                "message" => "Phone number must contain only digits, optionally starting with '+', and be 8 to 15 digits long."
            ]);
            exit;
        }
    } else {
        $data["phoneNumber"] = "null";
    }

    // Validate Password
    if (!preg_match("/^.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$/", $data["password"])) {
        echo json_encode([
            "code" => "000",
            "message" => "Password must be at least 8 characters and must contain at least one lowercase letter, one uppercase letter, and one digit."
        ]);
        exit;
    }

    // Metadata
    $signUpDate = date('c');
    $signUpDeviceIP = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $signUpDeviceBrowserAndOS = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $accountType = "Basic";
    $activationID = md5(sha1($businessEmail . "logs_Acc_Ver_Auth_ID" . $signUpDate));

    // IP Converter Functions
    function ipConverter($ip)
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            return 0;
        return sprintf("%u", ip2long($ip));
    }

    function inet_ntoa($num)
    {
        $num = trim($num);
        if ($num == "0")
            return "0.0.0.0";
        return long2ip(-(4294967295 - ($num - 1)));
    }

    // Final Data Payload
    $signUpData = [
        "businessName" => $businessName,
        "businessEmail" => $businessEmail,
        "businessCountry" => $data["businessCountry"],
        "businessState" => $data["businessState"],
        "businessAddress" => $businessAddress,
        "firstName" => $firstName,
        "lastName" => $lastName,
        "phoneNumber" => $data["phoneNumber"],
        "password" => $data["password"],
        "signUpDate" => $signUpDate,
        "signUpDeviceIP" => $signUpDeviceIP,
        "signUpDeviceBrowserAndOS" => $signUpDeviceBrowserAndOS,
        "lastLoginDate" => $signUpDate,
        "lastLoginDeviceIP" => $signUpDeviceIP,
        "lastLoginDeviceBrowserAndOS" => $signUpDeviceBrowserAndOS,
        "accountType" => $accountType,
        "activationID" => $activationID,
        "status" => "01"
    ];

    // Save to DB
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->signUp(
        $signUpData,
        "logsinv1_Business_Account_Table",
        "businessName, businessEmail, businessCountry, businessState, businessAddress, firstName, lastName, phoneNumber, password, signUpDate, signUpDeviceIP, signUpDeviceBrowserAndOS, lastLoginDate, lastLoginDeviceIP, lastLoginDeviceBrowserAndOS, accountType, activationID, status"
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// LOGS API LOGIN 
########################################################################################################################################################################################
if ($data["key"] === "login") {
    // BACKEND INPUT VALIDATIONS

    //CHECK FOR ANY EMPTY REQUIRED INPUT
    if (empty($data["email"]) || empty($data["password"])) {
        $code = "000";
        $message = "Please Enter Appropriate Values For All Required * Fields!";
        echo json_encode(array("code" => $code, "message" => $message));
        exit;

    }

    //VALIDATE EMAIL INPUT
    $email = $data["email"];
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $code = "000";
        $message = "Please enter a valid email address";
        echo json_encode(array("code" => $code, "message" => $message));
        exit;
    }

    //VALIDATE PASSWORD
    if (preg_match("/^.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$/", $data["password"]) === 0) {

        $code = "000";
        $message = "Password must be at least 8 characters and must contain at least one lower case letter, one upper case letter and one digit";
        echo json_encode(array("code" => $code, "message" => $message));
        exit;

    }

    /*$lastLoginDate = date("c");
    $lastLoginDeviceIP = @$_SERVER['REMOTE_ADDR'];
    $lastLoginDeviceBrowserAndOS = "@$_SERVER[HTTP_USER_AGENT]";*/

    $loginData = array("email" => $data["email"], "password" => $data["password"]);
    //$deviceData = array("lastLoginDate" => $lastLoginDate, "lastLoginDeviceIP" => $lastLoginDeviceIP, "lastLoginDeviceBrowserAndOS" => $lastLoginDeviceBrowserAndOS);

    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->login($loginData, "users", "id, email, password");

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// LOGS API RESET PASSWORD 
########################################################################################################################################################################################
if ($data["key"] === "RESET_ACCOUNT_PASSWORD") {

    // === Input validation helper ===
    function isValidPassword($password): bool
    {
        return preg_match("/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/", $password);
    }

    function respondWithError($message)
    {
        echo json_encode(["code" => "000", "message" => $message]);
        exit;
    }

    // === Extract Inputs ===
    $current_password = trim($data["current_password"] ?? '');
    $new_password = trim($data["password"] ?? '');
    $confirm_password = trim($data["confirm_password"] ?? '');
    $token = $data["token"] ?? '';

    // === Required Field Check ===
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        respondWithError("Please enter appropriate values for all required * fields!");
    }

    // === Validate Password Formats ===
    if (!isValidPassword($current_password)) {
        respondWithError("Password must be at least 8 characters and include a lowercase letter, an uppercase letter, and a number.");
    }

    if (!isValidPassword($new_password)) {
        respondWithError("Password must be at least 8 characters and include a lowercase letter, an uppercase letter, and a number.");
    }

    if (!isValidPassword($confirm_password)) {
        respondWithError("Password must be at least 8 characters and include a lowercase letter, an uppercase letter, and a number.");
    }

    // === Check Password Match ===
    if ($new_password !== $confirm_password) {
        respondWithError("New password and confirm password mismatch.");
    }

    // === Prepare Data and Proceed with DB Operation ===
    $reset_password_data = [
        "current_password" => $current_password,
        "password" => $new_password
    ];

    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->resetPassword($reset_password_data, "users", "id, password", $token);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// CREATE NEW USER/EMPLOYEE ACCOUNT
########################################################################################################################################################################################
if ($data["key"] === "createNewUser") {

    // Trim all inputs first
    $first_name = trim($data["first_name"] ?? '');
    $last_name = trim($data["last_name"] ?? '');
    $username = trim($data["username"] ?? '');
    $role = trim($data["role"] ?? '');
    $email = trim($data["email"] ?? '');
    $phone = trim($data["phone"] ?? '');
    $password = $data["password"] ?? ''; // do not trim passwords

    // Validate required fields
    if (
        $first_name === '' || $last_name === '' || $username === '' ||
        $role === '' || $email === '' || $phone === '' || $password === ''
    ) {
        echo json_encode(["code" => "000", "message" => "Please enter appropriate values for all required * fields!"]);
        exit;
    }

    // Validate name lengths (allow any character)
    if (strlen($first_name) > 50) {
        echo json_encode(["code" => "000", "message" => "First name must not exceed 50 characters."]);
        exit;
    }

    if (strlen($last_name) > 50) {
        echo json_encode(["code" => "000", "message" => "Last name must not exceed 50 characters."]);
        exit;
    }

    if (strlen($username) > 50) {
        echo json_encode(["code" => "000", "message" => "Username must not exceed 50 characters."]);
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(["code" => "000", "message" => "Please enter a valid email address."]);
        exit;
    }

    // Validate phone number (allow +, digits, spaces, hyphens)
    if (!preg_match('/^\+?[0-9\s\-]{8,20}$/', $phone)) {
        echo json_encode([
            "code" => "009",
            "message" => "Phone number must be 8 to 20 characters and may contain digits, spaces, hyphens, and optional leading '+'."
        ]);
        exit;
    }

    // Validate password
    if (preg_match("/^.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$/", $password) === 0) {
        echo json_encode([
            "code" => "000",
            "message" => "Password must be at least 8 characters and include one lowercase letter, one uppercase letter, and one digit."
        ]);
        exit;
    }

    // Validate role
    $validPermissions = ['1', '2', '3'];
    if (!in_array($role, $validPermissions)) {
        echo json_encode(["code" => "000", "message" => "Invalid selection for role."]);
        exit;
    }

    // Setup other metadata
    $createdOn = date("c");
    $lastLoginDeviceIP = $_SERVER['REMOTE_ADDR'] ?? '';
    $lastLoginDeviceBrowserAndOS = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $status = "01";
    $userToken = $data["token"] ?? '';

    // Prepare user data
    $newUserData = [
        "first_name" => $first_name,
        "last_name" => $last_name,
        "username" => $username,
        "role" => $role,
        "email" => $email,
        "phone" => $phone,
        "password" => $password,
        "created_at" => $createdOn
    ];

    // DB connection
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->createNewUser($newUserData, $userToken);
    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH USERS
########################################################################################################################################################################################
if ($data["key"] === "GET_USERS_DATA") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchUsers($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// CREATE CATEGORY
########################################################################################################################################################################################
if ($data["key"] === "CREATE_CATEGORY") {

    // === INPUT VALIDATION ===

    // Trim inputs
    $name = trim($data["name"] ?? '');
    $status = trim($data["status"] ?? '');

    // Required fields check
    if ($name === '' || $status === '') {
        echo json_encode([
            "code" => "000",
            "message" => "Please enter appropriate values for all required * fields!"
        ]);
        exit;
    }

    // Validate name length
    if (strlen($name) > 100) {
        echo json_encode([
            "code" => "000",
            "message" => "Category name must not exceed 100 characters."
        ]);
        exit;
    }

    // Allowed status values
    $validStatuses = ['active', 'inactive'];
    if (!in_array(strtolower($status), $validStatuses)) {
        echo json_encode([
            "code" => "000",
            "message" => "Invalid selection for status"
        ]);
        exit;
    }

    // === DATA PREPARATION ===
    $categoryData = [
        "name" => $name,
        "status" => strtolower($status)
    ];

    $userToken = $data["token"];

    // === DATABASE OPERATION ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->createCategory($categoryData, $userToken);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH CATEGORY
########################################################################################################################################################################################
if ($data["key"] === "GET_CATEGORIES") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchCategory($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// UPDATE CATEGORY
########################################################################################################################################################################################
if ($data["key"] === "UPDATE_CATEGORY") {

    // === INPUT PREP & VALIDATION ===

    // Trim inputs
    $name = trim($data["name"] ?? '');
    $status = trim($data["status"] ?? '');
    $id = trim($data["id"] ?? '');

    // Required input validation
    if ($name === '' || $status === '' || $id === '') {
        echo json_encode([
            "code" => "000",
            "message" => "Please enter appropriate values for all required * fields!"
        ]);
        exit;
    }

    // Validate name length (e.g., max 100 chars)
    if (mb_strlen($name) > 100) {
        echo json_encode([
            "code" => "000",
            "message" => "Category name must not exceed 100 characters."
        ]);
        exit;
    }

    // Allowed status values
    $validStatuses = ['active', 'inactive'];
    if (!in_array(strtolower($status), $validStatuses)) {
        echo json_encode([
            "code" => "000",
            "message" => "Invalid selection for status."
        ]);
        exit;
    }

    // === DATA PREPARATION ===
    $categoryData = [
        "name" => $name,
        "status" => strtolower($status),
        "id" => $id
    ];

    $userToken = $data["token"];

    // === DATABASE OPERATION ===
    $db = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $db->updateCategory(
        $categoryData,
        "categories",
        "name, status",
        $userToken
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// DELETE CATEGORY
########################################################################################################################################################################################
if ($data["key"] === "DELETE_CATEGORY") {
    // Validate required inputs
    if (empty($data["id"]) || empty($data["token"])) {
        echo json_encode(["code" => "000", "message" => "Missing category ID or token"]);
        exit;
    }

    $category_id = $data["id"];
    $userToken = $data["token"];

    $categoryData = ["id" => $category_id];

    // Create DB connection
    $db = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Call deletion method
    $output = $db->deleteCategory($categoryData, "categories", "deleted_at", $userToken);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// ADD NEW ADDRESS TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if (isset($data["key"]) && strtoupper($data["key"]) === "ADD_NEW_ADDRESS") {

    // === INPUT PREP ===
    $country = trim($data["country"] ?? '');
    $state = trim($data["state"] ?? '');
    $street = trim($data["street"] ?? '');
    $token = trim($data["token"] ?? '');

    // === HELPER RESPONSE ===
    function respond($message, $code = "000")
    {
        echo json_encode(["code" => $code, "message" => $message]);
        exit;
    }

    // === VALIDATE REQUIRED FIELDS ===
    if ($country === '' || $state === '' || $street === '') {
        respond("Please enter appropriate values for all required * fields!");
    }

    // === VALIDATE LENGTH ===
    if (mb_strlen($street) > 250) {
        respond("Street address must not exceed 250 characters.");
    }

    if (mb_strlen($country) > 100 || mb_strlen($state) > 100) {
        respond("Country and State must not exceed 100 characters each.");
    }

    // === BASIC NAME VALIDATION FOR COUNTRY/STATE ===
    $alphaPattern = "/^[\p{L}][\p{L}\s'-]*$/u"; // Supports Unicode letters

    if (!preg_match($alphaPattern, $country)) {
        respond("Country must start with a letter and contain only letters, spaces, apostrophes, or dashes.");
    }

    if (!preg_match($alphaPattern, $state)) {
        respond("State must start with a letter and contain only letters, spaces, apostrophes, or dashes.");
    }

    // === PREPARE DATA ===
    $newAddressData = [
        "country" => $country,
        "state" => $state,
        "street" => $street
    ];

    // === DB CONNECTION & INSERT ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->addNewAddress(
        $newAddressData,
        "address",
        "business_id, country, state, street, status, updated_at, created_at",
        $token
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH WAREHOUSES
########################################################################################################################################################################################
if ($data["key"] === "GET_ADDRESSES") {
    // Validate required input
    if (empty($data["token"])) {
        echo json_encode([
            "code" => "000",
            "message" => "Missing user token"
        ]);
        exit;
    }

    // Initialize DB connection
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Fetch addresses
    $response = $databaseConnection->fetchAddresses($data["token"]);

    // Return response
    echo json_encode($response);
    exit;
}


########################################################################################################################################################################################
// UPDATE LOCATION
########################################################################################################################################################################################
if ($data["key"] === "UPDATE_LOCATION") {
    // === Trim Input Values ===
    $country = trim($data["country"] ?? '');
    $state = trim($data["state"] ?? '');
    $street = trim($data["street"] ?? '');
    $token = trim($data["token"] ?? '');

    // === Helper Function ===
    function respond($message, $code = "000")
    {
        echo json_encode(["code" => $code, "message" => $message]);
        exit;
    }

    // === Required Fields Check ===
    if ($country === '' || $state === '' || $street === '') {
        respond("Please enter appropriate values for all required * fields!");
    }

    // === Length Validation ===
    if (mb_strlen($country) > 100 || mb_strlen($state) > 100) {
        respond("Country and State must not exceed 100 characters each.");
    }

    if (mb_strlen($street) > 250) {
        respond("Street address must not exceed 250 characters.");
    }

    // === Country/State Basic Character Validation (Allow international names) ===
    $alphaPattern = "/^[\p{L}][\p{L}\s'-]*$/u"; // Unicode-aware letters

    if (!preg_match($alphaPattern, $country)) {
        respond("Country must start with a letter and contain only letters, spaces, apostrophes, or dashes.");
    }

    if (!preg_match($alphaPattern, $state)) {
        respond("State must start with a letter and contain only letters, spaces, apostrophes, or dashes.");
    }

    // === Prepare Data ===
    $updateAddressData = [
        "country" => $country,
        "state" => $state,
        "street" => $street,
        "id" => $data["id"]
    ];

    // === Database Connection ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // === Execute Update ===
    $output = $databaseConnection->updateLocation(
        $updateAddressData,
        "address",
        "business_id, country, state, street, status, updated_at",
        $token
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// DELETE LOCATION
########################################################################################################################################################################################
if ($data["key"] === "DELETE_LOCATION") {
    // Validate required inputs
    if (empty($data["id"]) || empty($data["token"])) {
        echo json_encode(["code" => "000", "message" => "Missing category ID or token"]);
        exit;
    }

    $category_id = $data["id"];
    $userToken = $data["token"];

    $categoryData = ["id" => $category_id];

    // Create DB connection
    $db = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Call deletion method
    $output = $db->deleteLocation($categoryData, "address", "deleted_at", $userToken);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// ADD SUPPLIER
########################################################################################################################################################################################
if ($data["key"] === "ADD_SUPPLIER") {
    // === Helper Function ===
    function respond($message, $code = "000")
    {
        echo json_encode(["code" => $code, "message" => $message]);
        exit;
    }

    // === Trim Inputs ===
    $name = trim($data["name"] ?? '');
    $email = trim($data["email"] ?? '');
    $category = trim($data["category"] ?? '');
    $phone = trim($data["phone"] ?? '');
    $website = trim($data["website"] ?? '');
    $token = trim($data["token"] ?? '');

    // === Check Required Fields ===
    if ($name === '' || $email === '' || $category === '' || $phone === '') {
        respond("Please enter appropriate values for all required * fields!");
    }

    // === Validate Name ===
    if (mb_strlen($name) > 150) {
        respond("Supplier name must not exceed 150 characters.");
    }

    // === Validate Category ===
    $validCategories = ['manufacturer', 'wholesaler', 'retailer'];
    if (!in_array($category, $validCategories)) {
        respond("Invalid selection for supplier category.");
    }

    // === Validate Email ===
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        respond("Please enter a valid email address.");
    }

    // === Validate Phone Number ===
    $digitsOnly = preg_replace('/[^\d]/', '', $phone);
    if (strlen($digitsOnly) < 8 || strlen($digitsOnly) > 20) {
        respond("Phone number must contain 8 to 20 digits. Spaces and hyphens are allowed.");
    }
    if (!preg_match('/^[\d\s\-+]+$/', $phone)) {
        respond("Phone number may only contain digits, spaces, hyphens, and an optional leading '+'.");
    }

    // === Validate Website (Optional) ===
    if ($website === '') {
        $website = null;
    } else {
        if (
            !filter_var($website, FILTER_VALIDATE_URL) &&
            !preg_match("/^(www\.)?[a-z0-9\-]+(\.[a-z]{2,})+$/i", $website)
        ) {
            respond("Supplier website must be a valid URL (e.g., https://example.com or www.example.com).");
        }
    }

    // === Prepare Data ===
    $supplierData = [
        "name" => $name,
        "email" => $email,
        "category" => $category,
        "phone" => $phone,
        "website" => $website
    ];

    // === Database Connection ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->addSupplier(
        $supplierData,
        "suppliers",
        "business_id, name, email, category, phone, website, status, created_at, updated_at",
        $token
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH SUPPLIER
########################################################################################################################################################################################
if ($data["key"] === "GET_SUPPLIERS") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchSupplier($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// UPDATE SUPPLIER
########################################################################################################################################################################################
if ($data["key"] === "UPDATE_SUPPLIER") {
    // CHECK FOR ANY EMPTY REQUIRED INPUT
    if (empty($data["name"]) || empty($data["email"]) || empty($data["category"]) || empty($data["phone"])) {
        echo json_encode([
            "code" => "000",
            "message" => "Please Enter Appropriate Values For All Required * Fields!"
        ]);
        exit;
    }

    // VALIDATE SUPPLIER WEBSITE
    if (empty($data["website"])) {
        $data["website"] = "NULL";
    }

    // VALIDATE NAME: allow all characters, trim and check length
    $name = trim($data["name"]);
    if (strlen($name) < 1 || strlen($name) > 150) {
        echo json_encode([
            "code" => "000",
            "message" => "Supplier name must be between 1 and 150 characters."
        ]);
        exit;
    }

    // Validate category
    $validStatuses = ['manufacturer', 'wholesaler', 'retailer'];
    if (!in_array($data["category"], $validStatuses)) {
        echo json_encode([
            "code" => "000",
            "message" => "Invalid selection for supplier category"
        ]);
        exit;
    }

    // VALIDATE EMAIL
    if (!filter_var($data["email"], FILTER_VALIDATE_EMAIL)) {
        echo json_encode([
            "code" => "000",
            "message" => "Please enter a valid email address"
        ]);
        exit;
    }

    // VALIDATE PHONE: allow digits, spaces, and hyphens, length after removing space and hyphen = 8–20
    $rawPhone = $data["phone"];
    $strippedPhone = preg_replace('/[\s\-]/', '', $rawPhone); // remove spaces and hyphens
    if (!preg_match('/^[\d\s\-+]+$/', $rawPhone) || strlen($strippedPhone) < 8 || strlen($strippedPhone) > 20) {
        echo json_encode([
            "code" => "009",
            "message" => "Phone number must contain 8 to 20 digits and may include spaces or hyphens."
        ]);
        exit;
    }

    // VALIDATE WEBSITE
    if (
        !filter_var($data["website"], FILTER_VALIDATE_URL) &&
        !preg_match("/^(www\.)?[a-z0-9\-]+(\.[a-z]{2,})+$/i", $data["website"])
    ) {
        echo json_encode([
            "code" => "000",
            "message" => "Supplier Website must be a valid URL (e.g., https://example.com or www.example.com)"
        ]);
        exit;
    }

    // Compile cleaned data
    $supplierData = [
        "id" => $data["id"],
        "name" => $name,
        "email" => $data["email"],
        "category" => $data["category"],
        "phone" => $rawPhone,
        "website" => $data["website"],
        "status" => $data["status"]
    ];

    $userToken = $data["token"];

    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->updateSupplier(
        $supplierData,
        "suppliers",
        "business_id, name, email, category, phone, website, status, updated_at",
        $userToken
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// DELETE SUPPLIER
########################################################################################################################################################################################
if ($data["key"] === "DELETE_SUPPLIER") {
    // Validate required inputs
    if (empty($data["id"]) || empty($data["token"])) {
        echo json_encode(["code" => "000", "message" => "Missing Supplier ID or token"]);
        exit;
    }

    $supplier_id = $data["id"];
    $userToken = $data["token"];

    $supplierData = ["id" => $supplier_id];

    // Create DB connection
    $db = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Call deletion method
    $output = $db->deleteSupplier($supplierData, "suppliers", "deleted_at", $userToken);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH PRODUCT
########################################################################################################################################################################################
if ($data["key"] === "GET_PRODUCTS") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchProduct($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// ADD NEW PRODUCT TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if ($_POST["key"] === "ADD_NEW_PRODUCT") {
    // SERVER SIDE VALIDATION
    $requiredFields = ["name", "category", "cost_price", "price", "stock_alert", "description", "token"];

    foreach ($requiredFields as $field) {
        if (empty($_POST[$field])) {
            echo json_encode([
                "code" => "000",
                "message" => "Please enter appropriate values for all required * fields!"
            ]);
            exit;
        }
    }

    $name = trim($_POST["name"]);
    $category = $_POST["category"];
    $cost_price = $_POST["cost_price"];
    $price = $_POST["price"];
    $discount_price = isset($_POST['discount_price']) && $_POST['discount_price'] !== '' ? $_POST['discount_price'] : 0;
    $stock_alert = $_POST["stock_alert"];
    $description = trim($_POST["description"]);
    $vat = $_POST["vat"];
    $token = $_POST["token"];

    // VALIDATE LENGTHS
    if (strlen($name) < 2 || strlen($name) > 100) {
        echo json_encode([
            "code" => "000",
            "message" => "Product Name must be between 2 and 100 characters."
        ]);
        exit;
    }

    if (strlen($description) < 5 || strlen($description) > 2000) {
        echo json_encode([
            "code" => "000",
            "message" => "Product Description must be between 5 and 2000 characters."
        ]);
        exit;
    }

    // VALIDATE CATEGORY
    if (!preg_match("/^[0-9]+$/", $category)) {
        echo json_encode([
            "code" => "000",
            "message" => "Invalid product category value"
        ]);
        exit;
    }

    // VALIDATE COST PRICE, PRICE, DISCOUNT PRICE
    $decimalPattern = "/^\d+(\.\d{1,2})?$/";

    if (!preg_match($decimalPattern, $cost_price)) {
        echo json_encode([
            "code" => "000",
            "message" => "Cost Price must be a valid number (e.g. 100 or 100.50)"
        ]);
        exit;
    }

    if (!preg_match($decimalPattern, $price)) {
        echo json_encode([
            "code" => "000",
            "message" => "Product Price must be a valid number (e.g. 100 or 100.50)"
        ]);
        exit;
    }

    if (!preg_match($decimalPattern, $discount_price)) {
        echo json_encode([
            "code" => "000",
            "message" => "Discount Price must be a valid number"
        ]);
        exit;
    }

    // VALIDATE STOCK ALERT
    if (!preg_match("/^[0-9]+$/", $stock_alert)) {
        echo json_encode([
            "code" => "000",
            "message" => "Product Stock Alert must only contain numbers"
        ]);
        exit;
    }

    // VALIDATE VAT
    if (!in_array($vat, ["0", "1"], true)) {
        echo json_encode([
            "code" => "000",
            "message" => "Invalid selection for VAT"
        ]);
        exit;
    }

    // ✅ HANDLE IMAGE UPLOAD WITH VALIDATION & RESIZE
    $imageFileName = null;

    if (isset($_FILES['image']) && $_FILES['image']['error'] === 0) {
        $uploadDir = "uploads/products/";
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }

        $fileTmpPath = $_FILES['image']['tmp_name'];
        $fileSize = $_FILES['image']['size'];
        $fileType = mime_content_type($fileTmpPath);
        $allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        $maxFileSize = 5 * 1024 * 1024; // 5MB

        if (!in_array($fileType, $allowedTypes)) {
            echo json_encode([
                "code" => "000",
                "message" => "Invalid image type. Only JPG, JPEG, PNG, and WEBP allowed."
            ]);
            exit;
        }

        if ($fileSize > $maxFileSize) {
            echo json_encode([
                "code" => "000",
                "message" => "Image must be less than 5MB."
            ]);
            exit;
        }

        $ext = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
        $imageFileName = uniqid("prod_") . "." . strtolower($ext);
        $imagePath = $uploadDir . $imageFileName;

        list($width, $height) = getimagesize($fileTmpPath);
        $newWidth = 600;
        $newHeight = 600;

        $resizedImage = imagecreatetruecolor($newWidth, $newHeight);

        switch ($fileType) {
            case 'image/jpeg':
            case 'image/jpg':
                $sourceImage = imagecreatefromjpeg($fileTmpPath);
                break;
            case 'image/png':
                $sourceImage = imagecreatefrompng($fileTmpPath);
                imagealphablending($resizedImage, false);
                imagesavealpha($resizedImage, true);
                break;
            case 'image/webp':
                $sourceImage = imagecreatefromwebp($fileTmpPath);
                imagealphablending($resizedImage, false);
                imagesavealpha($resizedImage, true);
                break;
        }

        imagecopyresampled($resizedImage, $sourceImage, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);

        switch ($fileType) {
            case 'image/jpeg':
            case 'image/jpg':
                imagejpeg($resizedImage, $imagePath, 85);
                break;
            case 'image/png':
                imagepng($resizedImage, $imagePath, 8);
                break;
            case 'image/webp':
                imagewebp($resizedImage, $imagePath, 80);
                break;
        }

        imagedestroy($sourceImage);
        imagedestroy($resizedImage);
    }

    // ✅ PREPARE DATA FOR DATABASE
    $newProductData = [
        "name" => $name,
        "category_id" => $category,
        "cost_price" => $cost_price,
        "price" => $price,
        "discount_price" => $discount_price,
        "stock_alert" => $stock_alert,
        "description" => $description,
        "vat" => $vat,
        "image" => $imageFileName
    ];

    // ✅ DATABASE HANDLER
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->addNewProduct(
        $newProductData,
        "products",
        "business_id, name, category_id, cost_price, price, discount_price, stock_alert, description, vat, image, status, created_at, updated_at",
        $token
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// ADD NEW PRODUCT(S) FROM SPREADSHEET TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if ($data["key"] === "ADD_NEW_SPREADSHEET_PRODUCT") {
    $products = $data["product"];

    foreach ($products as $product) {
        // CHECK FOR REQUIRED FIELDS
        $requiredFields = ["name", "category_id", "cost_price", "price", "stock_alert", "description"];
        foreach ($requiredFields as $field) {
            if (empty($product[$field])) {
                echo json_encode(["code" => "000", "message" => "Please enter all required * fields!"]);
                exit;
            }
        }

        // NAME: Validate length only
        $productName = trim($product["name"]);
        if (strlen($productName) < 2 || strlen($productName) > 100) {
            echo json_encode(["code" => "000", "message" => "Product name must be between 2 and 100 characters."]);
            exit;
        }

        // CATEGORY_ID: Numbers only
        if (!preg_match("/^[0-9]+$/", $product["category_id"])) {
            echo json_encode(["code" => "000", "message" => "Invalid product category value."]);
            exit;
        }

        // COST PRICE
        if (!preg_match("/^\d+(\.\d{1,2})?$/", $product["cost_price"])) {
            echo json_encode(["code" => "000", "message" => "Cost Price must be a valid number (e.g. 100 or 100.50)."]);
            exit;
        }

        // PRODUCT PRICE
        if (!preg_match("/^\d+(\.\d{1,2})?$/", $product["price"])) {
            echo json_encode(["code" => "000", "message" => "Product Price must be a valid number (e.g. 100 or 100.50)."]);
            exit;
        }

        // DISCOUNT PRICE
        $discount_price = isset($product['discount_price']) && $product['discount_price'] !== '' ? $product['discount_price'] : 0;
        if (!preg_match("/^\d+(\.\d{1,2})?$/", $discount_price)) {
            echo json_encode(["code" => "000", "message" => "Discount Price must be a valid number (e.g. 100 or 100.50)."]);
            exit;
        }

        // STOCK ALERT
        if (!preg_match("/^[0-9]+$/", $product["stock_alert"])) {
            echo json_encode(["code" => "000", "message" => "Stock Alert must only contain whole numbers."]);
            exit;
        }

        // DESCRIPTION: Sanitize and validate length only
        $description = trim($product["description"]);
        if (strlen($description) < 5 || strlen($description) > 2000) {
            echo json_encode(["code" => "000", "message" => "Description must be between 5 and 2000 characters."]);
            exit;
        }

        // VAT must be boolean true/false
        if (!in_array($product["vat"], [true, false], true)) {
            echo json_encode(["code" => "000", "message" => "Invalid selection for VAT."]);
            exit;
        }

        // IMAGE (optional): validate extension
        if (!empty($product["image"])) {
            $allowedExtensions = ['png', 'jpg', 'jpeg', 'webp'];
            $imageExt = strtolower(pathinfo($product["image"], PATHINFO_EXTENSION));
            if (!in_array($imageExt, $allowedExtensions)) {
                echo json_encode(["code" => "000", "message" => "Only PNG, JPG, JPEG, or WEBP images are allowed."]);
                exit;
            }
        }

        $userToken = $data["token"];

        $newProductData = [
            "name" => $productName,
            "category_id" => $product["category_id"],
            "cost_price" => $product["cost_price"],
            "price" => $product["price"],
            "discount_price" => $discount_price,
            "stock_alert" => $product["stock_alert"],
            "description" => $description,
            "vat" => $product["vat"],
            "image" => $product["image"] ?? null,
        ];

        $databaseConnection = new LogsIMS(
            $config['host'],
            $config['username'],
            $config['password'],
            $config['database']
        );

        $output = $databaseConnection->addNewProduct(
            $newProductData,
            "products",
            "business_id, name, category_id, cost_price, price, discount_price, stock_alert, description, vat, image, status, created_at, updated_at",
            $userToken
        );
    }

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH GALLERY PRODUCTS
########################################################################################################################################################################################
if ($data["key"] === "GET_GALLERY_PRODUCTS") {

    $businessId = $data["business_id"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchGalleryProducts($businessId);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// UPDATE PRODUCT
########################################################################################################################################################################################
if ($_POST["key"] === "UPDATE_PRODUCT") {
    $requiredFields = ["id", "name", "category", "cost_price", "price", "stock_alert", "description", "vat", "token"];
    foreach ($requiredFields as $field) {
        if (!isset($_POST[$field]) || trim($_POST[$field]) === '') {
            echo json_encode(["code" => "000", "message" => ucfirst($field) . " is required"]);
            exit;
        }
    }

    // Extract
    $id = $_POST['id'];
    $name = trim($_POST["name"]);
    $category = $_POST["category"];
    $cost_price = $_POST["cost_price"];
    $price = $_POST["price"];
    $discount_price = isset($_POST['discount_price']) && $_POST['discount_price'] !== '' ? $_POST['discount_price'] : 0;
    $stock_alert = $_POST["stock_alert"];
    $description = trim($_POST["description"]);
    $vat = $_POST["vat"];
    $token = $_POST["token"];

    // Validations
    if (strlen($name) < 2 || strlen($name) > 100) {
        echo json_encode(["code" => "000", "message" => "Product name must be 2 to 100 characters long"]);
        exit;
    }

    if (!preg_match("/^[0-9]+$/", $category)) {
        echo json_encode(["code" => "000", "message" => "Invalid product category"]);
        exit;
    }

    if (!preg_match("/^\d+(\.\d{1,2})?$/", $cost_price)) {
        echo json_encode(["code" => "000", "message" => "Cost Price must be a valid number"]);
        exit;
    }

    if (!preg_match("/^\d+(\.\d{1,2})?$/", $price)) {
        echo json_encode(["code" => "000", "message" => "Product Price must be a valid number"]);
        exit;
    }

    if (!preg_match("/^\d+(\.\d{1,2})?$/", $discount_price)) {
        echo json_encode(["code" => "000", "message" => "Discount Price must be numeric"]);
        exit;
    }

    if (!preg_match("/^\d+$/", $stock_alert)) {
        echo json_encode(["code" => "000", "message" => "Stock Alert must be numeric"]);
        exit;
    }

    if (strlen($description) < 5 || strlen($description) > 2000) {
        echo json_encode(["code" => "000", "message" => "Description must be 5 to 2000 characters long"]);
        exit;
    }

    if (!in_array($vat, ["0", "1"], true)) {
        echo json_encode(["code" => "000", "message" => "Invalid VAT selection"]);
        exit;
    }

    // DB Connection
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Image Upload
    $imageName = null;
    if (isset($_FILES['image']) && $_FILES['image']['error'] === 0) {
        $uploadDir = "uploads/products/";
        if (!is_dir($uploadDir))
            mkdir($uploadDir, 0755, true);

        $fileTmpPath = $_FILES['image']['tmp_name'];
        $fileSize = $_FILES['image']['size'];
        $fileType = mime_content_type($fileTmpPath);
        $allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        $maxFileSize = 5 * 1024 * 1024;

        if (!in_array($fileType, $allowedTypes)) {
            echo json_encode(["code" => "000", "message" => "Only JPG, PNG, or WEBP images are allowed"]);
            exit;
        }

        if ($fileSize > $maxFileSize) {
            echo json_encode(["code" => "000", "message" => "Image must be less than 5MB"]);
            exit;
        }

        $ext = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
        $imageName = uniqid("prod_") . "." . strtolower($ext);
        $imagePath = $uploadDir . $imageName;

        list($width, $height) = getimagesize($fileTmpPath);
        $newWidth = 600;
        $newHeight = 600;
        $resizedImage = imagecreatetruecolor($newWidth, $newHeight);

        switch ($fileType) {
            case 'image/jpeg':
            case 'image/jpg':
                $sourceImage = imagecreatefromjpeg($fileTmpPath);
                break;
            case 'image/png':
                $sourceImage = imagecreatefrompng($fileTmpPath);
                imagealphablending($resizedImage, false);
                imagesavealpha($resizedImage, true);
                break;
            case 'image/webp':
                $sourceImage = imagecreatefromwebp($fileTmpPath);
                imagealphablending($resizedImage, false);
                imagesavealpha($resizedImage, true);
                break;
            default:
                echo json_encode(["code" => "000", "message" => "Unsupported image type"]);
                exit;
        }

        imagecopyresampled($resizedImage, $sourceImage, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);

        switch ($fileType) {
            case 'image/jpeg':
            case 'image/jpg':
                imagejpeg($resizedImage, $imagePath, 85);
                break;
            case 'image/png':
                imagepng($resizedImage, $imagePath, 8);
                break;
            case 'image/webp':
                imagewebp($resizedImage, $imagePath, 80);
                break;
        }

        imagedestroy($sourceImage);
        imagedestroy($resizedImage);
    } else {
        // Retain existing image
        $databaseConnection->selectQuery("products", "image", "id = ?", [$id]);
        if ($databaseConnection->checkrow()) {
            $existing = $databaseConnection->fetchQuery();
            $imageName = $existing[0]['image'] ?? null;
        }
    }

    // Prepare and Update
    $updatedProductData = [
        "id" => $id,
        "name" => $name,
        "category_id" => $category,
        "cost_price" => $cost_price,
        "price" => $price,
        "discount_price" => $discount_price,
        "stock_alert" => $stock_alert,
        "description" => $description,
        "vat" => $vat,
        "image" => $imageName
    ];

    $output = $databaseConnection->updateRecord(
        $updatedProductData,
        "products",
        "business_id, name, category_id, cost_price, price, discount_price, stock_alert, description, vat, image, updated_at",
        $token
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// DELETE PRODUCT
########################################################################################################################################################################################
if ($data["key"] === "DELETE_PRODUCT") {
    // Validate required inputs
    if (empty($data["id"]) || empty($data["token"])) {
        echo json_encode(["code" => "000", "message" => "Missing Product ID or token"]);
        exit;
    }

    $product_id = $data["id"];
    $userToken = $data["token"];

    $productData = ["id" => $product_id];

    // Create DB connection
    $db = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Call deletion method
    $output = $db->deleteProduct($productData, "products", "deleted_at", $userToken);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// ADD NEW CUSTOMER
########################################################################################################################################################################################
if ($data["key"] === "ADD_NEW_CUSTOMER") {

    function respond(string $message, string $code = "000"): void
    {
        echo json_encode(["code" => $code, "message" => $message]);
        exit;
    }

    // Required Fields
    foreach (["first_name", "phone"] as $field) {
        if (empty($data[$field])) {
            respond("Please enter appropriate values for all required * fields!");
        }
    }

    // Trim and Normalize
    $firstName = trim($data["first_name"]);
    $phone = trim($data["phone"]);
    $lastName = isset($data["last_name"]) && trim($data["last_name"]) !== '' ? trim($data["last_name"]) : null;
    $country = isset($data["country"]) && trim($data["country"]) !== '' ? trim($data["country"]) : null;
    $state = isset($data["state"]) && trim($data["state"]) !== '' ? trim($data["state"]) : null;
    $street = isset($data["street"]) && trim($data["street"]) !== '' ? trim($data["street"]) : null;
    $token = trim($data["token"] ?? '');

    // Validation Patterns
    $genericNamePattern = "/^.{1,50}$/"; // Accepts anything, 1-50 chars
    $streetPattern = "/^.{1,250}$/";      // Any char, max 250
    $phonePattern = '/^[\d\s+\-]{8,20}$/'; // Allow digits, space, +, hyphen; 8-20 chars

    // Validate Required
    if (!preg_match($genericNamePattern, $firstName)) {
        respond("First name must be between 1 and 50 characters.");
    }

    // Strip non-digit characters to count numeric length
    $digitsOnly = preg_replace('/\D/', '', $phone);
    if (!preg_match($phonePattern, $phone) || strlen($digitsOnly) < 8 || strlen($digitsOnly) > 20) {
        respond("Phone number must contain 8 to 20 digits, and may include spaces or hyphens.", "009");
    }

    // Optional Validations
    if ($lastName !== null && !preg_match($genericNamePattern, $lastName)) {
        respond("Last name must be between 1 and 50 characters.");
    }
    if ($country !== null && !preg_match($genericNamePattern, $country)) {
        respond("Country must be between 1 and 100 characters.");
    }
    if ($state !== null && !preg_match($genericNamePattern, $state)) {
        respond("State must be between 1 and 100 characters.");
    }
    if ($street !== null && !preg_match($streetPattern, $street)) {
        respond("Street must be between 1 and 250 characters.");
    }

    // Prepare Customer Data
    $customerData = [
        "first_name" => $firstName,
        "last_name" => $lastName,
        "phone" => $phone,
        "country" => $country,
        "state" => $state,
        "street" => $street
    ];

    // Insert
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->addNewCustomer(
        $customerData,
        "customers",
        "business_id, first_name, last_name, phone, country, state, street, status, updated_at, created_at",
        $token
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH CUSTOMERS
########################################################################################################################################################################################
if ($data["key"] === "GET_CUSTOMERS") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchCustomers($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// ADD NEW SALE ORDER TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if ($data["key"] === "ADD_NEW_SALE_ORDER") {

    // === Helper Functions ===
    function respondError($message)
    {
        echo json_encode(["code" => "000", "message" => $message]);
        exit;
    }

    function isNumeric($value)
    {
        return is_numeric($value);
    }

    function validateRequiredFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || trim($data[$field]) === '') {
                respondError("Please enter appropriate values for all required * fields!");
            }
        }
    }

    function validateOptions($value, array $allowedOptions, $errorMessage)
    {
        if (!in_array($value, $allowedOptions)) {
            respondError($errorMessage);
        }
    }

    function validateNumericFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || !is_numeric($data[$field])) {
                $fieldName = ucwords(str_replace('_', ' ', $field));
                respondError("$fieldName must be a valid number (integer or decimal)");
            }
        }
    }

    // === Step 1: Validate Incoming Data ===
    validateRequiredFields(["product", "customer", "payment_status", "unit_price", "quantity_sold", "total_price"], $data);

    if (!ctype_digit(strval($data["product"]))) {
        respondError("Invalid product value");
    }

    if (!ctype_digit(strval($data["customer"]))) {
        respondError("Invalid customer value");
    }

    validateOptions($data["payment_status"], ["paid", "unpaid", "partially paid"], "Invalid selection for payment status");

    if ($data["payment_status"] === "partially paid") {
        validateRequiredFields(["amount_paid", "balance"], $data);
        validateNumericFields(["amount_paid", "balance"], $data);
    }

    validateNumericFields(["unit_price", "quantity_sold", "total_price"], $data);

    $discount = $data["discount_price"] ?? 0;
    if ($discount === '' || $discount === null) {
        $discount = 0;
    }
    if (!is_numeric($discount)) {
        respondError("Discount Price must be a valid number");
    }

    // === Step 2: Prepare Data ===
    $userToken = $data["token"];
    $newOrderData = [
        "product_id" => $data["product"],
        "customer_id" => $data["customer"],
        "payment_status" => $data["payment_status"],
        "unit_price" => (float) $data["unit_price"],
        "discount_price" => (float) $discount,
        "quantity_sold" => (float) $data["quantity_sold"],
        "total_price" => (float) $data["total_price"],
        "amount_paid" => isset($data["amount_paid"]) ? (float) $data["amount_paid"] : 0,
        "amount_remaining" => isset($data["balance"]) ? (float) $data["balance"] : 0,
    ];

    // === Step 3: Connect and Insert ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->addNewSalesOrder(
        $newOrderData,
        "sales_orders",
        "business_id, product_id, order_id, customer_id, payment_status, unit_price, discount_price, quantity_sold, total_price, amount_paid, amount_remaining, profit, status, created_at, updated_at",
        $userToken
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// ADD NEW CUSTOMER ORDER TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if ($data["key"] === "ADD_NEW_CUSTOMER_ORDER") {

    // === Helper Functions ===
    function respondError($message)
    {
        echo json_encode(["code" => "000", "message" => $message]);
        exit;
    }

    function validateRequiredFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (empty($data[$field])) {
                respondError("Please enter appropriate values for all required * fields!");
            }
        }
    }

    function validateCustomer(array $customer)
    {
        if (!is_array($customer))
            respondError("Customer data is invalid.");

        validateRequiredFields(["first_name", "last_name", "phone"], $customer);

        // Name validations (allow all characters, limit 1–100 chars)
        foreach (["first_name", "last_name"] as $field) {
            $value = trim($customer[$field]);
            if (strlen($value) < 1 || strlen($value) > 50) {
                respondError(ucwords(str_replace("_", " ", $field)) . " must be between 1 and 50 characters.");
            }
        }

        // Phone: digits, space, dash, length between 8–20
        if (!preg_match('/^[0-9\s-]{8,20}$/', $customer["phone"])) {
            respondError("Phone number must be 8 to 20 characters and may include digits, spaces, and dashes.");
        }

        // === Validate Phone Number ===
        $digitsOnly = preg_replace('/[^\d]/', '', $customer["phone"]);
        if (strlen($digitsOnly) < 8 || strlen($digitsOnly) > 20) {
            respond("Phone number must contain 8 to 20 digits. Spaces and hyphens are allowed.");
        }
        if (!preg_match('/^[\d\s\-+]+$/', $customer["phone"])) {
            respond("Phone number may only contain digits, spaces, hyphens, and an optional leading '+'.");
        }
    }

    function validateCart(array $cart)
    {
        if (!is_array($cart) || count($cart) === 0)
            respondError("Cart must contain at least one item.");

        foreach ($cart as $index => $item) {
            if (
                !isset($item["product_id"], $item["quantity"], $item["unit_price"], $item["total_price"]) ||
                !is_numeric($item["product_id"]) ||
                !is_numeric($item["quantity"]) ||
                !is_numeric($item["unit_price"]) ||
                !is_numeric($item["total_price"])
            ) {
                respondError("Invalid cart item at index $index.");
            }
        }
    }

    // === Step 1: Validate Data ===
    if (!isset($data["customer"], $data["cart"])) {
        respondError("Missing customer or cart data.");
    }

    validateCustomer($data["customer"]);
    validateCart($data["cart"]);

    // === Step 2: Connect and Add Customer ===
    $db = new LogsIMS($config['host'], $config['username'], $config['password'], $config['database']);
    $customerId = $db->addOrFindCustomer($data["customer"], $data["token"]);

    // === Step 3: Generate Shared order_id ===
    $orderId = $db->generateSequentialOrderId("sales", "sales_orders");
    $userToken = $data["token"] ?? null;

    // === Step 4: Insert Each Cart Item with Same order_id ===
    $allInserted = true;

    foreach ($data["cart"] as $item) {
        $newOrderData = [
            "product_id" => $item["product_id"],
            "customer_id" => $customerId,
            "payment_status" => "unpaid",
            "unit_price" => $item["unit_price"],
            "discount_price" => 0,
            "quantity_sold" => $item["quantity"],
            "total_price" => $item["total_price"],
            "amount_paid" => 0,
            "amount_remaining" => $item["total_price"],
            "order_id" => $orderId
        ];

        $result = $db->addNewSalesOrder(
            $newOrderData,
            "sales_orders",
            "business_id, product_id, order_id, customer_id, payment_status, unit_price, discount_price, quantity_sold, total_price, amount_paid, amount_remaining, profit, status, created_at, updated_at",
            $userToken
        );

        if ($result["code"] !== "001") {
            $allInserted = false;
            break;
        }
    }

    // === Step 5: Final Response ===
    if ($allInserted) {
        echo json_encode([
            "code" => "001",
            "message" => "Order successfully placed.",
            "order_id" => $orderId
        ]);
    } else {
        respondError("Failed to insert one or more sales records.");
    }

    exit;
}


########################################################################################################################################################################################
// FETCH SALES ORDERS
########################################################################################################################################################################################
if ($data["key"] === "GET_SALES_ORDERS") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchSalesOrders($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// UPDATE SALES ORDERS
########################################################################################################################################################################################
if ($data["key"] === "UPDATE_SALE") {

    // === Helper Functions (Scoped Locally) ===
    function respondError($message)
    {
        echo json_encode(["code" => "000", "message" => $message]);
        exit;
    }

    function isNumeric($value)
    {
        return is_numeric($value);
    }

    function validateRequiredFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || trim($data[$field]) === '') {
                respondError("Please enter appropriate values for all required * fields!");
            }
        }
    }

    function validateOptions($value, array $allowedOptions, $errorMessage)
    {
        if (!in_array($value, $allowedOptions, true)) {
            respondError($errorMessage);
        }
    }

    function validateNumericFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || !is_numeric($data[$field])) {
                $fieldName = ucwords(str_replace('_', ' ', $field));
                respondError("$fieldName must be a valid number or decimal.");
            }
        }
    }

    // === Step 1: Validate Incoming Data ===
    validateRequiredFields(["product", "customer", "payment_status", "unit_price", "quantity_sold", "total_price"], $data);

    if (!ctype_digit(strval($data["product"]))) {
        respondError("Invalid product value");
    }

    if (!ctype_digit(strval($data["customer"]))) {
        respondError("Invalid customer value");
    }

    if (!ctype_digit(strval($data["assigned_to"]))) {
        respondError("Invalid assigned user value");
    }

    validateOptions($data["payment_status"], ["paid", "unpaid", "partially paid"], "Invalid selection for payment status");

    if ($data["payment_status"] === "partially paid") {
        validateRequiredFields(["amount_paid", "balance"], $data);
        validateNumericFields(["amount_paid", "balance"], $data);
    }

    validateNumericFields(["unit_price", "quantity_sold", "total_price"], $data);

    // Optional: set discount_price = 0 if not sent or empty
    if (!isset($data["discount_price"]) || $data["discount_price"] === "") {
        $data["discount_price"] = 0;
    } else {
        validateNumericFields(["discount_price"], $data);
    }

    // Optional: fallback if amount_paid and balance are not set (for non-partial payments)
    $data["amount_paid"] = isset($data["amount_paid"]) && is_numeric($data["amount_paid"]) ? $data["amount_paid"] : 0;
    $data["balance"] = isset($data["balance"]) && is_numeric($data["balance"]) ? $data["balance"] : $data["total_price"];

    // === Step 2: Prepare Data ===
    $userToken = $data["token"];
    $newOrderData = [
        "id" => $data["id"],
        "product_id" => $data["product"],
        "customer_id" => $data["customer"],
        "payment_status" => $data["payment_status"],
        "unit_price" => number_format((float)$data["unit_price"], 2, '.', ''),
        "discount_price" => number_format((float)$data["discount_price"], 2, '.', ''),
        "quantity_sold" => (int)$data["quantity_sold"],
        "total_price" => number_format((float)$data["total_price"], 2, '.', ''),
        "amount_paid" => number_format((float)$data["amount_paid"], 2, '.', ''),
        "amount_remaining" => number_format((float)$data["balance"], 2, '.', ''),
        "assigned_to" => $data["assigned_to"]
    ];

    // === Step 3: Connect and Update Order ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->updateSalesOrder(
        $newOrderData,
        "sales_orders",
        "business_id, product_id, customer_id, payment_status, unit_price, discount_price, quantity_sold, total_price, amount_paid, amount_remaining, profit, assigned_to, status, updated_at",
        $userToken
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// DELETE SALES ORDER
########################################################################################################################################################################################
if ($data["key"] === "DELETE_SALE") {
    // Validate required inputs
    if (empty($data["id"]) || empty($data["token"])) {
        echo json_encode(["code" => "000", "message" => "Missing Sale ID or token"]);
        exit;
    }

    $sale_id = $data["id"];
    $userToken = $data["token"];

    $itemData = ["id" => $sale_id];

    // Create DB connection
    $db = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Call deletion method
    $output = $db->deleteItem($itemData, "sales_orders", "deleted_at", $userToken);

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// ADD NEW PURCHASE ORDER TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if ($data["key"] === "ADD_NEW_PURCHASE_ORDER") {

    // === Helper Functions (Scoped Locally) ===
    function respondError($message)
    {
        echo json_encode(["code" => "000", "message" => $message]);
        exit;
    }

    function isNumeric($value)
    {
        return is_numeric($value); // supports integers and decimals
    }

    function validateRequiredFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (empty($data[$field]) && $data[$field] !== "0" && $data[$field] !== 0) {
                respondError("Please enter appropriate values for all required * fields!");
            }
        }
    }

    function validateOptions($value, array $allowedOptions, $errorMessage)
    {
        if (!in_array($value, $allowedOptions)) {
            respondError($errorMessage);
        }
    }

    function validateNumericFields(array $fields, array $data)
    {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || !is_numeric($data[$field])) {
                $fieldName = ucwords(str_replace('_', ' ', $field));
                respondError("$fieldName must be a valid number");
            }
        }
    }

    // === Step 1: Validate Input Data ===
    validateRequiredFields(["product", "supplier", "location", "delivery_status", "unit_cost", "order_quantity", "total_cost"], $data);

    if (!isNumeric($data["product"])) {
        respondError("Invalid product value");
    }

    if (!isNumeric($data["supplier"])) {
        respondError("Invalid supplier value");
    }

    if (!isNumeric($data["location"])) {
        respondError("Invalid location value");
    }

    validateOptions($data["delivery_status"], ["pending", "received"], "Invalid selection for delivery status");

    validateNumericFields(["unit_cost", "order_quantity", "total_cost"], $data);

    // === Step 2: Prepare Data ===
    $userToken = $data["token"];
    $newOrderData = [
        "product_id" => $data["product"],
        "supplier_id" => $data["supplier"],
        "address_id" => $data["location"],
        "delivery_status" => $data["delivery_status"],
        "unit_cost" => $data["unit_cost"],
        "order_quantity" => $data["order_quantity"],
        "total_cost" => $data["total_cost"]
    ];

    // === Step 3: Execute DB Insert ===
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->addNewPurchaseOrder(
        $newOrderData,
        "purchase_orders",
        "business_id, product_id, order_id, supplier_id, address_id, delivery_status, unit_cost, order_quantity, total_cost, status, created_at, updated_at",
        $userToken
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH PURCHASE ORDERS
########################################################################################################################################################################################
if ($data["key"] === "GET_PURCHASE_ORDERS") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchPurchaseOrders($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// ADD NEW TRANSFER TO THE INVENTORY DATABASE
########################################################################################################################################################################################
if ($data["key"] === "ADD_NEW_TRANSFER") {

    // Helper to return a JSON error and exit
    function respond($message, $code = "000")
    {
        echo json_encode(["code" => $code, "message" => $message]);
        exit;
    }

    // Required input fields
    $requiredFields = ["product", "quantity", "from_address", "to_address", "assigned_to", "transfer_status"];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            respond("Please enter appropriate values for all required * fields!");
        }
    }

    // Prevent transferring to the same location
    if ($data["from_address"] == $data["to_address"]) {
        respond("Products cannot be moved to the same location.");
    }

    // Validate numeric fields
    $numericFields = [
        "product"       => "Invalid value for selected product",
        "quantity"      => "Product quantity must only contain numbers",
        "from_address"  => "Invalid value for selected address (From)",
        "to_address"    => "Invalid value for selected address (To)",
        "assigned_to"   => "Invalid value for selected assigned user"
    ];

    foreach ($numericFields as $field => $errorMessage) {
        if (!ctype_digit($data[$field])) {
            respond($errorMessage);
        }
    }

    // Validate transfer status
    $validStatuses = ["pending", "completed"];
    if (!in_array($data["transfer_status"], $validStatuses)) {
        respond("Invalid selection for transfer status");
    }

    // Prepare data for insertion
    $userToken = $data["token"];
    $newTransferData = [
        "product_id"      => $data["product"],
        "transfer_status" => $data["transfer_status"],
        "quantity"        => $data["quantity"],
        "from_address_id" => $data["from_address"],
        "to_address_id"   => $data["to_address"],
        "assigned_to"     => $data["assigned_to"]
    ];

    // Database connection
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    // Insert into transfers table
    $output = $databaseConnection->addNewTransfer(
        $newTransferData,
        "transfers",
        "business_id, product_id, transfer_status, quantity, from_address_id, to_address_id, assigned_to, status, created_at, updated_at",
        $userToken
    );

    echo json_encode($output);
    exit;
}


########################################################################################################################################################################################
// FETCH TRANSFERS
########################################################################################################################################################################################
if ($data["key"] === "GET_TRANSFERS") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchTransfers($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// FETCH ORDERS
########################################################################################################################################################################################
if ($data["key"] === "fetchOrders") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchOrders($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// FETCH USER DATA
########################################################################################################################################################################################
if ($data["key"] === "GET_USER_DATA") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->fetchUserData($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// GET INVENTORY VALUE
########################################################################################################################################################################################
if ($data["key"] === "GET_INVENTORY_VALUE") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->getInventoryValue($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// GET INVENTORY PROFIT
########################################################################################################################################################################################
if ($data["key"] === "GET_INVENTORY_PROFIT") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->getInventoryProfit($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// GET PRODUCT COUNT
########################################################################################################################################################################################
if ($data["key"] === "GET_PRODUCTS_COUNT") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->getProductsCount($userToken);

    echo json_encode($output);
    exit;

}


########################################################################################################################################################################################
// GET ORDER COUNT
########################################################################################################################################################################################
if ($data["key"] === "GET_ORDERS_COUNT") {

    $userToken = $data["token"];
    $databaseConnection = new LogsIMS(
        $config['host'],
        $config['username'],
        $config['password'],
        $config['database']
    );

    $output = $databaseConnection->getOrdersCount($userToken);

    echo json_encode($output);
    exit;

}


?>