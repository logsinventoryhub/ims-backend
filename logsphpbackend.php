<?php
require_once "vendor/autoload.php";
require_once "mysqllab.php";
require_once "jwt/JWT.php";
require_once "status.php";
require_once "roles.php";

use Firebase\JWT\JWT;

define("secret_key", "ez.F9~)UHxD?2~J");

class LogsIMS extends HandleSql
{
    private $host;
    private $username;
    private $password;
    private $database;
    private $connection = null;

    public function __construct($host, $username, $password, $database)
    {
        $this->host = $host;
        $this->username = $username;
        $this->password = $password;
        $this->database = $database;

        // Call parent constructor to initialize $this->conn_str
        parent::__construct($host, $username, $password, $database);
    }

    /**
     * Optional internal connection getter (if needed separately)
     */
    public function connect()
    {
        if ($this->connection === null) {
            $this->connection = new mysqli($this->host, $this->username, $this->password, $this->database);
            if ($this->connection->connect_error) {
                return false;
            }
        }
        return $this->connection;
    }

    public function addOrFindCustomer(array $customer, $businessId)
    {
        $cleaned = $this->clean([
            'business_id' => $businessId,
            'first_name' => $customer['first_name'],
            'last_name' => $customer['last_name'],
            'phone' => $customer['phone'],
        ]);

        [$businessId, $firstName, $lastName, $phone] = $cleaned;

        // Step 1: Check if customer exists
        $checkQuery = "SELECT id FROM customers WHERE phone = ?";
        $stmt = $this->conn_str->prepare($checkQuery);
        $stmt->bind_param("s", $phone);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result && $result->num_rows > 0) {
            $row = $result->fetch_assoc();
            return $row["id"]; // Existing customer ID
        }

        // Step 2: Insert new customer
        $insertQuery = "INSERT INTO customers (business_id, first_name, last_name, phone, created_at, updated_at) 
                        VALUES (?, ?, ?, ?, NOW(), NOW())";
        $stmt = $this->conn_str->prepare($insertQuery);
        $stmt->bind_param("ssss", $businessId, $firstName, $lastName, $phone);

        if ($stmt->execute()) {
            return $stmt->insert_id; // Return new customer ID
        } else {
            echo json_encode([
                "code" => "000",
                "message" => "Failed to add customer: " . $stmt->error
            ]);
            exit;
        }
    }

    public function checkExists(string $table, string $whereClause, array $params = []): bool
    {
        $sql = "SELECT 1 FROM `$table` WHERE $whereClause LIMIT 1";
        $stmt = $this->conn_str->prepare($sql);

        if (!$stmt)
            return false;

        if (!empty($params)) {
            $types = str_repeat('s', count($params));
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $stmt->store_result();
        $exists = $stmt->num_rows > 0;
        $stmt->close();

        return $exists;
    }

    public function enc(string $issuer, string $audience, string $id): string
    {
        $payload = [
            "iss" => $issuer,
            "aud" => $audience,
            "id" => $id,
            "iat" => time(),
            "nbf" => time()
        ];

        return JWT::encode($payload, secret_key, 'HS256');
    }

    private function generateUniqueCustomerId($table)
    {
        $maxAttempts = 10;
        $attempt = 0;
        $length = 6;
        $prefix = 'C_';
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        do {
            // Generate random 6-character alphanumeric ID with C_ prefix
            $randomCode = $prefix;
            for ($i = 0; $i < $length; $i++) {
                $randomCode .= $characters[random_int(0, strlen($characters) - 1)];
            }

            // Use your existing selectQuery() and checkrow() to verify uniqueness
            $whereClause = "WHERE customer_id = ?";
            $columns = "customer_id"; // Can be any column(s), you just need to run a query
            $params = [$randomCode];

            $this->selectQuery($table, $columns, $whereClause, $params);

            $exists = $this->checkrow() > 0;
            $attempt++;

        } while ($exists && $attempt < $maxAttempts);

        if ($exists) {
            throw new Exception("Failed to generate unique customer ID after $maxAttempts attempts.");
        }

        return $randomCode;
    }

    public function generateSequentialOrderId(string $orderType, string $table): string
    {
        $prefix = strtoupper($orderType) === 'SALES' ? 'SO-' : 'PO-';
        $likePattern = $prefix . '%';

        $sql = "SELECT order_id FROM $table WHERE order_id LIKE ? ORDER BY order_id DESC LIMIT 1";
        $stmt = $this->conn_str->prepare($sql);
        if (!$stmt) {
            die("Prepare failed: " . $this->conn_str->error);
        }

        $stmt->bind_param("s", $likePattern);
        if (!$stmt->execute()) {
            die("Execute failed: " . $stmt->error);
        }

        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        if ($row && isset($row['order_id'])) {
            $lastId = (int) str_replace($prefix, '', $row['order_id']);
            $newIdNumber = $lastId + 1;
        } else {
            $newIdNumber = 1;
        }

        $formattedId = $prefix . str_pad((string) $newIdNumber, 8, '0', STR_PAD_LEFT);
        return $formattedId;
    }

    public function getId($token)
    {
        $jwt = new JWT;
        $call = $jwt::decode($token, secret_key, array('HS256'));
        $decoded_array = (array) $call;

        return $decoded_array['id'] ?? null;
    }

    private function getBusinessIdFromToken($token)
    {
        $user_id = $this->getId($token);

        // Check if user is an active member
        $this->selectQuery(
            "members",
            "user_id, business_id",
            "WHERE user_id = ? AND deleted_at IS NULL",
            [$user_id]
        );

        if ($this->checkrow() !== 1) {
            return null;
        }

        $data = $this->fetchQuery();
        return $data[0]['business_id'] ?? null;
    }

    private function getAdminOrManagerBusinessIdFromToken($token)
    {
        $user_id = $this->getId($token);

        // Check if user is an active member
        $this->selectQuery(
            "members",
            "user_id, business_id",
            "WHERE user_id = ? AND (role_id = ? OR role_id = ?) AND deleted_at IS NULL",
            [$user_id, Roles::ROLE_ADMIN, Roles::ROLE_MANAGER]
        );

        if ($this->checkrow() !== 1) {
            return null;
        }

        $data = $this->fetchQuery();
        return $data[0]['business_id'] ?? null;
    }

    // LOGS SIGN UP METHOD
    public function signUp($signUpData, $table, $column)
    {
        // Step 1: Clean & validate user data
        $user_data = [
            "username" => $signUpData["businessName"],
            "email" => $signUpData["businessEmail"],
            "password" => $signUpData["password"],
            "created_at" => date('c')
        ];
        $clean_user_data = $this->clean($user_data);

        // Step 2: Check if business already exists
        $this->selectQuery("business", "name", "WHERE name=?", [
            $clean_user_data[0]
        ]);
        if ($this->checkrow() > 0) {
            return ["code" => "000", "message" => "Oops! Business Name already exists"];
        }

        // Step 3: Check if user already exists
        $this->selectQuery("users", "email", "WHERE email=?", [
            $clean_user_data[1]
        ]);
        if ($this->checkrow() > 0) {
            return ["code" => "000", "message" => "Oops! Email already exists"];
        }

        // Step 4: Insert into `users`
        $insert_user = $this->insertQuery("users", "username, email, password, created_at", $clean_user_data);
        if (!$insert_user) {
            return ["code" => "000", "message" => "Oops! Problem creating user account"];
        }
        $user_id = $this->conn_str->insert_id;

        // Step 5: Insert into `profile`
        $profile_data = [
            "user_id" => $user_id,
            "first_name" => $signUpData["firstName"],
            "last_name" => $signUpData["lastName"],
            "phone" => $signUpData["phoneNumber"],
            "created_at" => date('c')
        ];
        $clean_profile_data = $this->clean($profile_data);
        $insert_profile = $this->insertQuery("profile", "user_id, first_name, last_name, phone, created_at", $clean_profile_data);
        if (!$insert_profile) {
            return ["code" => "000", "message" => "Oops! Problem creating account profile"];
        }

        // Step 6: Check if business already exists
        $business_data = [
            "user_id" => $user_id,
            "name" => $signUpData["businessName"],
            //"email"    => $signUpData["businessEmail"],
            "street" => $signUpData["businessAddress"],
            "state" => $signUpData["businessState"],
            "country" => $signUpData["businessCountry"],
            "created_at" => date('c')
        ];
        $clean_business_data = $this->clean($business_data);
        $this->selectQuery("business", "id", "WHERE user_id=? AND name=?", [
            $user_id,
            $clean_business_data[1]
        ]);
        if ($this->checkrow() > 0) {
            return ["code" => "000", "message" => "Oops! Business already exists"];
        }

        // Step 7: Insert into `business`
        $insert_business = $this->insertQuery("business", "user_id, name, street, state, country, created_at", $clean_business_data);
        if (!$insert_business) {
            return ["code" => "000", "message" => "Oops! Problem creating business account"];
        }
        $business_id = $this->conn_str->insert_id;

        // Step 8: Insert into `members`
        $member_data = [
            "user_id" => $user_id,
            "business_id" => $business_id,
            "role_id" => 1,
            "created_at" => date('c')
        ];
        $clean_member_data = $this->clean($member_data);
        $insert_member = $this->insertQuery("members", "user_id, business_id, role_id, created_at", $clean_member_data);
        if (!$insert_member) {
            return ["code" => "000", "message" => "Oops! Problem creating account membership"];
        }

        return ["code" => "001", "message" => "Hurray! Account successfully created"];
    }


    // LOGS LOGIN METHOD
    public function login($loginData, $table, $column)
    {
        // Sanitize username input to prevent SQL injection
        $email = $this->conn_str->real_escape_string($loginData['email']);
        $password = $loginData['password'];

        $where = "WHERE email='$email'";
        $this->selectQuery($table, $column, $where);

        if ($this->checkrow() == 1) {
            $fetched_user_data = $this->fetchQuery();

            $storedHashedPassword = $fetched_user_data[0]['password'];

            // Verify password against hashed password
            if ($this->verify_password($password, $storedHashedPassword)) {
                // Prepare JWT payload data
                $issuer = "http://localhost";
                $audience = "http://localhost/dashboard";
                $user_id = $fetched_user_data[0]['id'];  // Correctly get user id

                // Generate JWT token
                $token = $this->enc($issuer, $audience, $user_id);

                // Optionally update device info here, if needed

                return array(
                    "code" => "001",
                    "message" => "Success! Accessing Account Control Dashboard",
                    "token" => $token
                );
            } else {
                return array(
                    "code" => "000",
                    "message" => "Oops! Sorry, we couldn't find an account with those credentials."
                );
            }
        } else {
            return array(
                "code" => "000",
                "message" => "Oops! Sorry, we couldn't find an account with those credentials."
            );
        }
    }

    // LOGS RESET PASSWORD METHOD
    public function resetPassword($reset_password_data, $table, $columns, $token)
    {
        $user_id = $this->getId($token);

        if (!$user_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid User"
            ];
        }

        // Fetch existing user data
        $where = "WHERE id = ?";
        $params = [$user_id];
        $this->selectQuery($table, $columns, $where, $params);

        if ($this->checkrow() !== 1) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid User"
            ];
        }

        $fetched_user_data = $this->fetchQuery();
        $storedHashedPassword = $fetched_user_data[0]['password'];

        // Verify current password
        if (!$this->verify_password($reset_password_data['current_password'], $storedHashedPassword)) {
            return [
                "code" => "000",
                "message" => "Oops! Wrong passcode entry"
            ];
        }

        // Validate that the new password isn't the same as the current password
        if ($reset_password_data["current_password"] === $reset_password_data["password"]) {
            return [
                "code" => "000",
                "message" => "Oops! Use a different password from the old one"
            ];
        }

        // Hash and sanitize new password
        $newPasswordData = [
            "password" => $reset_password_data["password"],
            "updated_at" => date('c')
        ];

        $cleanedData = $this->cleanUpdateData($newPasswordData);
        $updateSuccess = $this->updateQuery($table, $cleanedData, $where, $params);

        if ($updateSuccess) {
            return [
                "code" => "001",
                "message" => "Hurray! Password successfully updated"
            ];
        } else {
            return [
                "code" => "000",
                "message" => "Oops! Problem updating password"
            ];
        }
    }

    // LOGS CREATE NEW USER METHOD
    public function createNewUser($new_user_data, $token)
    {
        // Decode token and get user ID of requester (must be admin/role 1)
        $decoded_user_id = $this->getId($token);
        if (!$decoded_user_id) {
            return ["code" => "000", "message" => "Access Denied: invalid token"];
        }

        // Verify logged-in user has admin role (role_id = 1) in members table
        $this->selectQuery("members", "user_id, business_id, role_id", "WHERE user_id = ? AND role_id = '1'", [$decoded_user_id]);
        if ($this->checkrow() !== 1) {
            return ["code" => "000", "message" => "Access Denied: insufficient permissions"];
        }
        $admin_member_data = $this->fetchQuery()[0];

        // Check if username or email already exists
        $this->selectQuery("users", "id", "WHERE email = ?", [$new_user_data["email"]]);
        if ($this->checkrow() > 0) {
            return ["code" => "000", "message" => "Oops! Email already in use"];
        }

        // Prepare user data for insert, hash password, clean input
        $user_data = [
            "username" => $new_user_data["username"],
            "email" => $new_user_data["email"],
            "password" => $new_user_data["password"], // will be hashed in clean()
            "created_at" => date('c')
        ];
        $clean_user_data = $this->clean($user_data);

        // Insert user
        $insert_user = $this->insertQuery(
            "users",
            "username, email, password, created_at",
            $clean_user_data
        );

        if (!$insert_user) {
            return ["code" => "000", "message" => "Oops! Problem creating user account", "mysql_error" => $this->conn_str->error];
        }

        // Get inserted user's ID
        $new_user_id = $this->conn_str->insert_id;

        // Prepare and insert profile data
        $profile_data = [
            "user_id" => $new_user_id,
            "first_name" => $new_user_data["first_name"],
            "last_name" => $new_user_data["last_name"],
            "phone" => $new_user_data["phone"],
            "created_at" => date('c')
        ];
        $clean_profile_data = $this->clean($profile_data);

        $insert_profile = $this->insertQuery(
            "profile",
            "user_id, first_name, last_name, phone, created_at",
            $clean_profile_data
        );

        if (!$insert_profile) {
            return ["code" => "000", "message" => "Oops! Problem creating user profile", "mysql_error" => $this->conn_str->error];
        }

        // Prepare and insert member data
        $member_data = [
            "user_id" => $new_user_id,
            "business_id" => $admin_member_data["business_id"],
            "role_id" => $new_user_data["role"],
            "created_at" => date('c')
        ];
        $clean_member_data = $this->clean($member_data);

        $insert_member = $this->insertQuery(
            "members",
            "user_id, business_id, role_id, created_at",
            $clean_member_data
        );

        if (!$insert_member) {
            return ["code" => "000", "message" => "Oops! Problem creating user member record", "mysql_error" => $this->conn_str->error];
        }

        return ["code" => "001", "message" => "Hurray! Account successfully created"];
    }

    // LOGS FETCH USER , PROFILE, BUSINESS DATA METHOD
    public function fetchUserData($token)
    {
        $user_id = $this->getId($token);

        if (!$user_id) {
            return ["code" => "000", "message" => "Invalid token"];
        }

        $user_data = $this->getSingleRecord("users", "username, email, email_verified_at, updated_at, deleted_at, created_at", "id = '$user_id'");
        if (!$user_data) {
            return ["code" => "000", "message" => "Invalid user"];
        }

        $profile_data = $this->getSingleRecord("profile", "first_name, last_name, phone, phone_verified_at, street, city, state, country, post_code, metadata, updated_at, deleted_at, created_at", "user_id = '$user_id'");
        if (!$profile_data) {
            return ["code" => "000", "message" => "User profile not found"];
        }

        $member_data = $this->getSingleRecord("members", "id, business_id, role_id, updated_at, deleted_at, created_at", "user_id = '$user_id'");
        if (!$member_data) {
            return ["code" => "000", "message" => "Membership record not found"];
        }

        $business_id = $member_data[0]['business_id'];
        $business_data = $this->getSingleRecord("business", "id, name, category, description, street, city, state, country, post_code, metadata, updated_at, deleted_at, created_at", "id = '$business_id'");
        if (!$business_data) {
            return ["code" => "000", "message" => "Business record not found"];
        }

        $categories = $this->fetchCategory($token);

        $locations = $this->fetchAddresses($token);

        //$products = $this->fetchProduct($token);

        return [
            "code" => "001",
            "message" => "Success",
            "user" => $user_data,
            "profile" => $profile_data,
            "member" => $member_data,
            "business" => $business_data,
            "categories" => $categories,
            "locations" => $locations,
            //"products" => $products
        ];
    }

    // Helper method to avoid repetition
    private function getSingleRecord($table, $fields, $whereClause)
    {
        $this->selectQuery($table, $fields, "WHERE $whereClause AND deleted_at IS NULL");
        return $this->checkrow() === 1 ? $this->fetchQuery() : null;
    }

    // LOGS FETCH USERS/EMPLOYEE METHOD
    public function fetchUsers(string $token): array
    {
        // Step 1: Authenticate user and get their business ID
        $business_id = $this->getAdminOrManagerBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Query users related to the business with specific roles (1 or 2)
        $this->selectJoinQuery(
            "members", // base table only
            "users.id, users.username, users.email, profile.first_name, profile.last_name, profile.phone, roles.name AS role_name",
            "JOIN users ON users.id = members.user_id
     JOIN profile ON profile.user_id = users.id
     JOIN roles ON roles.id = members.role_id",
            "members.business_id = ? AND members.deleted_at IS NULL",
            [$business_id]
        );


        // Step 3: Fetch results or return empty array
        $userList = $this->checkrow() > 0 ? $this->fetchQuery() : [];

        return [
            "code" => "001",
            "message" => "Success",
            "users" => $userList
        ];
    }




    // LOGS CREATE CATEGORY METHOD
    public function createCategory($category_data, $token)
    {
        // Step 1: Authenticate user and get their business ID
        $business_id = $this->getBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }


        // Step 2: Prepare category data
        $now = date('c');
        $new_category = [
            "business_id" => $business_id,
            "name" => $category_data["name"],
            "status" => $category_data["status"],
            "created_at" => $now,
            "updated_at" => $now
        ];

        $clean_category_data = $this->clean($new_category);
        $status = Status::ACTIVE;

        // Step 3: Check for existing category
        $this->selectQuery(
            "categories",
            "business_id, name, status, created_at, updated_at",
            "WHERE business_id = ? AND name = ? AND status = ? AND deleted_at IS NULL",
            [$business_id, $clean_category_data["name"], $status]
        );

        if ($this->checkrow() > 0) {
            return [
                "code" => "000",
                "message" => "Oops! Category already exists"
            ];
        }

        // Step 4: Insert new category
        $columns = "business_id, name, status, created_at, updated_at";
        if (!$this->insertQuery("categories", $columns, $clean_category_data)) {
            return [
                "code" => "000",
                "message" => "Oops! Problem creating category"
            ];
        }

        return [
            "code" => "001",
            "message" => "Hurray! Category successfully created"
        ];
    }

    // LOGS FETCH CATEGORY METHOD
    public function fetchCategory($token)
    {
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "003",
                "message" => "Invalid token or business not found."
            ];
        }

        // Use selectQuery to prepare the statement
        $this->selectQuery(
            "categories",
            "id, name, status, created_at",
            "WHERE business_id = '$businessId' AND deleted_at IS NULL"
        );

        // Check and return result
        if ($this->checkrow() > 0) {
            $categories = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $categories
            ];
        }

        return [
            "code" => "000",
            "message" => "No categories found.",
        ];
    }

    // LOGS UPDATE CATEGORY METHOD
    public function updateCategory($category_data, $table, $column, $token)
    {
        // Step 1: Authenticate and get business ID
        $business_id = $this->getBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Sanitize and prepare update data
        $updateData = [
            "name" => $category_data["name"],
            "status" => $category_data["status"],
            "updated_at" => date('c')
        ];
        $cleanData = $this->cleanUpdateData($updateData);

        // Step 3: Validate existence of the category by ID
        $checkSql = "SELECT $column FROM $table WHERE business_id = ? AND id = ?";
        $stmt = $this->conn_str->prepare($checkSql);
        $stmt->bind_param("ss", $business_id, $category_data["id"]);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid category",
                "id" => $category_data["id"],
            ];
        }

        // Step 4: Check for duplicate name (excluding the current category ID)
        $dupSql = "SELECT id FROM $table WHERE business_id = ? AND name = ? AND id != ? AND deleted_at IS NULL";
        $dupStmt = $this->conn_str->prepare($dupSql);
        $dupStmt->bind_param("sss", $business_id, $cleanData["name"], $category_data["id"]);
        $dupStmt->execute();
        $dupResult = $dupStmt->get_result();

        if ($dupResult->num_rows > 0) {
            return [
                "code" => "000",
                "message" => "Oops! A category with that name already exists"
            ];
        }

        // Step 5: Update the category
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $category_data["id"]];

        $updated = $this->updateQuery($table, $cleanData, $whereClause, $whereParams);

        if ($updated) {
            return [
                "code" => "001",
                "message" => "Hurray! Category successfully updated"
            ];
        } else {
            return [
                "code" => "000",
                "message" => "Oops! Problem updating category"
            ];
        }
    }


    // LOGS DELETE CATEGORY METHOD
    public function deleteCategory($category_data, $table, $column, $token)
    {
        // Step 1: Get business ID
        $business_id = $this->getBusinessIdFromToken($token);
        if (!$business_id) {
            return ["code" => "000", "message" => "Oops! Invalid user"];
        }

        // Step 2: Sanitize soft-delete data
        $deleteData = [
            "deleted_at" => date('c'),
            "updated_at" => date('c')
        ];
        $clean_delete_data = $this->cleanUpdateData($deleteData);

        // Step 3: Build WHERE clause and parameter list
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $category_data["id"]];

        // Step 4: Verify category exists
        $checkSql = "SELECT $column FROM $table $whereClause";
        $checkStmt = $this->conn_str->prepare($checkSql);

        if (!$checkStmt) {
            return ["code" => "000", "message" => "SQL prepare failed: " . $this->conn_str->error];
        }

        $checkStmt->bind_param("ss", $business_id, $category_data["id"]);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        // Step 5: If found, soft-delete it
        if ($result && $result->num_rows === 1) {
            $deleted = $this->updateQuery($table, $clean_delete_data, $whereClause, $whereParams);

            return $deleted
                ? ["code" => "001", "message" => "Hurray! Category successfully deleted"]
                : ["code" => "000", "message" => "Oops! Problem deleting category"];
        } else {
            return ["code" => "000", "message" => "Oops! Invalid Category"];
        }
    }

    // LOGS ADD NEW AADRESS METHOD
    public function addNewAddress(array $newAddressData, string $table, string $columns, string $token): array
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Prepare address data
        $timestamp = date('c');
        $status = Status::ACTIVE;

        $addressRecord = [
            "business_id" => $businessId,
            "country" => $newAddressData["country"],
            "state" => $newAddressData["state"],
            "street" => $newAddressData["street"],
            "status" => $status,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        $cleanData = $this->clean($addressRecord);

        // Step 3: Check for existing address
        $whereClause = "WHERE business_id = ? AND country = ? AND state = ? AND street = ? AND deleted_at IS NULL";
        $bindParams = [
            $businessId,
            $cleanData["country"],
            $cleanData["state"],
            $cleanData["street"]
        ];

        $this->selectQuery($table, $columns, $whereClause, $bindParams);

        if ($this->checkrow() > 0) {
            return [
                "code" => "000",
                "message" => "Oops! Address already exists"
            ];
        }

        // Step 4: Insert new address
        $insertSuccess = $this->insertQuery($table, $columns, $cleanData);

        if (!$insertSuccess) {
            return [
                "code" => "000",
                "message" => "Oops! Problem adding address"
            ];
        }

        return [
            "code" => "001",
            "message" => "Hurray! Address successfully added"
        ];
    }

    // LOGS FETCH ADDRESSES METHOD
    public function fetchAddresses($token)
    {
        // Step 1: Get business ID from token
        $business_id = $this->getBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Invalid token or unauthorized access"
            ];
        }

        // Step 2: Fetch addresses safely with prepared parameters
        $columns = "id, country, state, street, status, created_at";
        $whereClause = "WHERE business_id = ? AND deleted_at IS NULL";
        $params = [$business_id];

        $this->selectQuery("address", $columns, $whereClause, $params);

        // Step 3: Return data or a friendly message
        if ($this->checkrow() > 0) {
            $addresses = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $addresses
            ];
        }

        return [
            "code" => "000",
            "message" => "No address found"
        ];
    }

    // LOGS UPDATE CATEGORY METHOD
    public function updateLocation($locationData, $table, $column, $token)
    {
        // Step 1: Authenticate and get business ID
        $business_id = $this->getBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Sanitize and prepare update data
        $updateData = [
            "country" => $locationData["country"],
            "state" => $locationData["state"],
            "street" => $locationData["street"],
            "updated_at" => date('c')
        ];
        $cleanData = $this->cleanUpdateData($updateData);

        // Step 3: Validate existence of the location by ID
        $checkSql = "SELECT $column FROM $table WHERE business_id = ? AND id = ?";
        $stmt = $this->conn_str->prepare($checkSql);
        $stmt->bind_param("ss", $business_id, $locationData["id"]);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid location",
                "id" => $locationData["id"],
            ];
        }

        // Step 4: Check for duplicate name (excluding the current location ID)
        $dupSql = "SELECT id FROM $table WHERE business_id = ? AND country = ? AND state = ? AND street = ? AND id != ? AND deleted_at IS NULL";
        $dupStmt = $this->conn_str->prepare($dupSql);
        $dupStmt->bind_param("sss", $business_id, $cleanData["country"], $cleanData["state"], $cleanData["street"], $locationData["id"]);
        $dupStmt->execute();
        $dupResult = $dupStmt->get_result();

        if ($dupResult->num_rows > 0) {
            return [
                "code" => "000",
                "message" => "Oops! A location with that detail already exists"
            ];
        }

        // Step 5: Update the location
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $locationData["id"]];

        $updated = $this->updateQuery($table, $cleanData, $whereClause, $whereParams);

        if ($updated) {
            return [
                "code" => "001",
                "message" => "Hurray! Location successfully updated"
            ];
        } else {
            return [
                "code" => "000",
                "message" => "Oops! Problem updating location"
            ];
        }
    }


    // LOGS DELETE CATEGORY METHOD
    public function deleteLocation($locationData, $table, $column, $token)
    {
        // Step 1: Get business ID
        $business_id = $this->getBusinessIdFromToken($token);
        if (!$business_id) {
            return ["code" => "000", "message" => "Oops! Invalid user"];
        }

        // Step 2: Sanitize soft-delete data
        $deleteData = [
            "deleted_at" => date('c'),
        ];
        $clean_delete_data = $this->cleanUpdateData($deleteData);

        // Step 3: Build WHERE clause and parameter list
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $locationData["id"]];

        // Step 4: Verify location exists
        $checkSql = "SELECT $column FROM $table $whereClause";
        $checkStmt = $this->conn_str->prepare($checkSql);

        if (!$checkStmt) {
            return ["code" => "000", "message" => "SQL prepare failed: " . $this->conn_str->error];
        }

        $checkStmt->bind_param("ss", $business_id, $locationData["id"]);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        // Step 5: If found, soft-delete it
        if ($result && $result->num_rows === 1) {
            $deleted = $this->updateQuery($table, $clean_delete_data, $whereClause, $whereParams);

            return $deleted
                ? ["code" => "001", "message" => "Hurray! Location successfully deleted"]
                : ["code" => "000", "message" => "Oops! Problem deleting location"];
        } else {
            return ["code" => "000", "message" => "Oops! Invalid Location"];
        }
    }

    // LOGS ADD SUPPLIER METHOD
    public function addSupplier($supplierData, $table, $column, $token)
    {

        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Prepare supplier data
        $timestamp = date('c');
        $status = Status::ACTIVE;

        $supplierRecord = [
            "business_id" => $businessId,
            "name" => $supplierData["name"],
            "email" => $supplierData["email"],
            "category" => $supplierData["category"],
            "phone" => $supplierData["phone"],
            "website" => $supplierData["website"],
            "status" => $status,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        $cleanData = $this->clean($supplierRecord);

        // Step 3: Check for existing supplier
        $whereClause = "WHERE business_id = ? AND name = ? AND email = ? AND deleted_at IS NULL";
        $bindParams = [
            $businessId,
            $cleanData[1],
            $cleanData[2]
        ];

        $this->selectQuery($table, $column, $whereClause, $bindParams);

        if ($this->checkrow() > 0) {
            return [
                "code" => "000",
                "message" => "Oops! Supplier already exists"
            ];
        }

        // Step 4: Insert new supplier
        $insertSuccess = $this->insertQuery($table, $column, $cleanData);

        if (!$insertSuccess) {
            return [
                "code" => "000",
                "message" => "Oops! Problem adding supplier"
            ];
        }

        return [
            "code" => "001",
            "message" => "Hurray! Supplier and product successfully added"
        ];


    }

    // FETCH SUPPLIER METHOD
    public function fetchSupplier($token)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        $whereClause = "business_id = '$businessId' AND deleted_at IS NULL";

        $this->selectQuery(
            "suppliers",
            "id, name, category, email, phone, website, status, created_at",
            $whereClause
        );

        if ($this->checkrow() > 0) {
            $suppliers = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $suppliers
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No supplier found!"
            ];
        }
    }

    // LOGS UPDATE CATEGORY METHOD
    public function updateSupplier($supplierData, $table, $column, $token)
    {
        // Step 1: Authenticate and get business ID
        $business_id = $this->getBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Sanitize and prepare update data
        $timestamp = date('c');
        $status = Status::ACTIVE;
        $updateData = [
            "business_id" => $business_id,
            "name" => $supplierData["name"],
            "email" => $supplierData["email"],
            "category" => $supplierData["category"],
            "phone" => $supplierData["phone"],
            "website" => $supplierData["website"],
            "status" => $supplierData["status"],
            "updated_at" => $timestamp
        ];
        $cleanData = $this->cleanUpdateData($updateData);

        // Step 3: Validate existence of the category by ID
        $checkSql = "SELECT $column FROM $table WHERE business_id = ? AND id = ?";
        $stmt = $this->conn_str->prepare($checkSql);
        $stmt->bind_param("ss", $business_id, $supplierData["id"]);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid supplier",
                "id" => $supplierData["id"],
            ];
        }

        // Step 4: Check for duplicate name (excluding the current supplier ID)
        $dupSql = "SELECT id FROM $table WHERE business_id = ? AND email = ? AND id != ? AND deleted_at IS NULL";
        $dupStmt = $this->conn_str->prepare($dupSql);
        $dupStmt->bind_param("sss", $business_id, $cleanData["email"], $supplierData["id"]);
        $dupStmt->execute();
        $dupResult = $dupStmt->get_result();

        if ($dupResult->num_rows > 0) {
            return [
                "code" => "000",
                "message" => "Oops! A supplier with that name or email already exists"
            ];
        }

        // Step 5: Update the category
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $supplierData["id"]];

        $updated = $this->updateQuery($table, $cleanData, $whereClause, $whereParams);

        if ($updated) {
            return [
                "code" => "001",
                "message" => "Hurray! Supplier successfully updated"
            ];
        } else {
            return [
                "code" => "000",
                "message" => "Oops! Problem updating supplier"
            ];
        }
    }


    // LOGS DELETE SUPPLIER METHOD
    public function deleteSupplier($supplierData, $table, $column, $token)
    {
        // Step 1: Get business ID
        $business_id = $this->getBusinessIdFromToken($token);
        if (!$business_id) {
            return ["code" => "000", "message" => "Oops! Invalid user"];
        }

        // Step 2: Sanitize soft-delete data
        $deleteData = [
            "deleted_at" => date('c'),
            "updated_at" => date('c')
        ];
        $clean_delete_data = $this->cleanUpdateData($deleteData);

        // Step 3: Build WHERE clause and parameter list
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $supplierData["id"]];

        // Step 4: Verify supplier exists
        $checkSql = "SELECT $column FROM $table $whereClause";
        $checkStmt = $this->conn_str->prepare($checkSql);

        if (!$checkStmt) {
            return ["code" => "000", "message" => "SQL prepare failed: " . $this->conn_str->error];
        }

        $checkStmt->bind_param("ss", $business_id, $supplierData["id"]);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        // Step 5: If found, soft-delete it
        if ($result && $result->num_rows === 1) {
            $deleted = $this->updateQuery($table, $clean_delete_data, $whereClause, $whereParams);

            return $deleted
                ? ["code" => "001", "message" => "Hurray! Supplier successfully deleted"]
                : ["code" => "000", "message" => "Oops! Problem deleting supplier"];
        } else {
            return ["code" => "000", "message" => "Oops! Invalid Supplier"];
        }
    }


    // LOGS FETCH PRODUCTS METHOD
    public function fetchProduct($token)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        /*$whereClause = "business_id = '$businessId' AND deleted_at IS NULL";

        $this->selectQuery(
            "products",
            "id, name, category_id, price, quantity, stock_alert, supplier_id, vat, status, created_at",
            $whereClause
        );*/

        $this->selectJoinQuery(
            "products", // base table only
            "products.id, products.name, categories.name AS category, products.price, products.cost_price, products.discount_price, products.stock_alert, products.image, products.description, products.vat, products.status, products.created_at",
            "JOIN categories ON categories.id = products.category_id",
            "products.business_id = ? AND products.deleted_at IS NULL",
            [$businessId]
        );

        if ($this->checkrow() > 0) {
            $products = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $products
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No product found!"
            ];
        }
    }


    // LOGS ADD NEW PRODUCT METHOD
    public function addNewProduct($newProductData, $table, $column, $token)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);
        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Check if product already exists (by name + category)
        $this->selectQuery(
            $table,
            "id",
            "WHERE business_id = ? AND name = ? AND category_id = ? AND deleted_at IS NULL",
            [$businessId, $newProductData["name"], $newProductData["category_id"]]
        );

        if ($this->checkrow() > 0) {
            return [
                "code" => "000",
                "message" => "A product with this name already exists in the selected category."
            ];
        }

        // Step 3: Calculate VAT
        $price = $newProductData["price"];
        if ($newProductData["vat"] === true || $newProductData["vat"] === "1" || $newProductData["vat"] === 1) {
            $vatRate = 7.5; // VAT %
            $vatAmount = $price * ($vatRate / 100);
            $price = round($price + $vatAmount, 2);
        }

        // Step 4: Prepare full product record
        $timestamp = date('c');
        $status = Status::ACTIVE;

        $productRecord = [
            "business_id" => $businessId,
            "name" => $newProductData["name"],
            "category_id" => $newProductData["category_id"],
            "cost_price" => $newProductData["cost_price"],
            "price" => $price,
            "discount_price" => $newProductData["discount_price"],
            "stock_alert" => $newProductData["stock_alert"],
            "description" => $newProductData["description"],
            "vat" => $newProductData["vat"],
            "image" => $newProductData["image"] ?? null,
            "status" => $status,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        // Step 5: Clean data and dynamically create column list
        $cleanData = $this->clean($productRecord);
        $column = implode(', ', array_keys($productRecord)); // matches cleaned data order

        // Step 6: Insert into database
        $insertSuccess = $this->insertQuery($table, $column, $cleanData);

        if (!$insertSuccess) {
            return [
                "code" => "000",
                "message" => "Oops! Problem adding product"
            ];
        }

        return [
            "code" => "001",
            "message" => "Hurray! Product successfully added"
        ];
    }


    // LOGS FETCH PRODUCTS METHOD
    public function fetchGalleryProducts($businessId)
    {
        $table = "products p";

        $columns = "
        p.id,
        p.name AS product_name,
        c.name AS category_name,
        COALESCE(po.total_purchased, 0) - COALESCE(so.total_sold, 0) AS total_quantity,
        p.price,
        p.discount_price,
        p.image,
        p.vat,
        p.status,
        p.stock_alert,
        p.created_at
    ";

        $joins = "
        LEFT JOIN (
            SELECT product_id, SUM(order_quantity) AS total_purchased
            FROM purchase_orders
            WHERE business_id = ? AND deleted_at IS NULL
            GROUP BY product_id
        ) po ON po.product_id = p.id

        LEFT JOIN (
            SELECT product_id, SUM(quantity_sold) AS total_sold
            FROM sales_orders
            WHERE business_id = ? AND deleted_at IS NULL
            GROUP BY product_id
        ) so ON so.product_id = p.id

        JOIN categories c ON c.id = p.category_id
    ";

        $where = "p.business_id = ? AND p.deleted_at IS NULL";

        $params = [$businessId, $businessId, $businessId];

        $this->selectJoinQuery($table, $columns, $joins, $where, $params);

        if ($this->checkrow() > 0) {
            $products = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $products
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No product found!"
            ];
        }
    }

    // LOGS DELETE PRODUCT METHOD
    public function deleteProduct($productData, $table, $column, $token)
    {
        // Step 1: Get business ID
        $business_id = $this->getBusinessIdFromToken($token);
        if (!$business_id) {
            return ["code" => "000", "message" => "Oops! Invalid user"];
        }

        // Step 2: Sanitize soft-delete data
        $deleteData = [
            "deleted_at" => date('c'),
            "updated_at" => date('c')
        ];
        $clean_delete_data = $this->cleanUpdateData($deleteData);

        // Step 3: Build WHERE clause and parameter list
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $productData["id"]];

        // Step 4: Verify product exists
        $checkSql = "SELECT $column FROM $table $whereClause";
        $checkStmt = $this->conn_str->prepare($checkSql);

        if (!$checkStmt) {
            return ["code" => "000", "message" => "SQL prepare failed: " . $this->conn_str->error];
        }

        $checkStmt->bind_param("ss", $business_id, $productData["id"]);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        // Step 5: If found, soft-delete it
        if ($result && $result->num_rows === 1) {
            $deleted = $this->updateQuery($table, $clean_delete_data, $whereClause, $whereParams);

            return $deleted
                ? ["code" => "001", "message" => "Hurray! Product successfully deleted"]
                : ["code" => "000", "message" => "Oops! Problem deleting product"];
        } else {
            return ["code" => "000", "message" => "Oops! Invalid product"];
        }
    }

    // LOGS DELETE ITEM METHOD
    public function deleteItem($itemData, $table, $column, $token)
    {
        // Step 1: Get business ID
        $business_id = $this->getBusinessIdFromToken($token);
        if (!$business_id) {
            return ["code" => "000", "message" => "Oops! Invalid user"];
        }

        // Step 2: Sanitize soft-delete data
        $deleteData = [
            "deleted_at" => date('c'),
            "updated_at" => date('c')
        ];
        $clean_delete_data = $this->cleanUpdateData($deleteData);

        // Step 3: Build WHERE clause and parameter list
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $itemData["id"]];

        // Step 4: Verify product exists
        $checkSql = "SELECT $column FROM $table $whereClause";
        $checkStmt = $this->conn_str->prepare($checkSql);

        if (!$checkStmt) {
            return ["code" => "000", "message" => "SQL prepare failed: " . $this->conn_str->error];
        }

        $checkStmt->bind_param("ss", $business_id, $itemData["id"]);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        // Step 5: If found, soft-delete it
        if ($result && $result->num_rows === 1) {
            $deleted = $this->updateQuery($table, $clean_delete_data, $whereClause, $whereParams);

            return $deleted
                ? ["code" => "001", "message" => "Hurray! Item successfully deleted"]
                : ["code" => "000", "message" => "Oops! Problem deleting item"];
        } else {
            return ["code" => "000", "message" => "Oops! Invalid item"];
        }
    }



    // LOGS ADD NEW CUSTOMER METHOD
    public function addNewCustomer($newCustomerData, $table, $column, $token)
    {
        // Step 1: Authenticate and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Generate a unique customer_id in the format "C_XXXXXX"
        // $customerId = $this->generateUniqueCustomerId($table);

        // Step 3: Build customer record
        $timestamp = date('c');
        $customerRecord = [
            "business_id" => $businessId,
            "first_name" => $newCustomerData["first_name"],
            "last_name" => $newCustomerData["last_name"],
            "phone" => $newCustomerData["phone"],
            "country" => $newCustomerData["country"] ?? null,
            "state" => $newCustomerData["state"] ?? null,
            "street" => $newCustomerData["street"] ?? null,
            "status" => Status::ACTIVE,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        // Step 4: Clean data
        $cleanData = $this->clean($customerRecord);

        // Step 5: Check for existing customer by phone
        $whereClause = "WHERE business_id = ? AND phone = ? AND deleted_at IS NULL";
        $bindParams = [$businessId, $cleanData[3]];
        $this->selectQuery($table, $column, $whereClause, $bindParams);

        if ($this->checkrow() > 0) {
            return [
                "code" => "000",
                "message" => "Oops! Customer already exists"
            ];
        }

        // Step 6: Insert new customer
        $inserted = $this->insertQuery($table, $column, $cleanData);

        if (!$inserted) {
            return [
                "code" => "000",
                "message" => "Oops! Problem adding customer"
            ];
        }

        return [
            "code" => "001",
            "message" => "Hurray! Customer successfully added"
        ];
    }


    // LOGS FETCH CUSTOMERS METHOD
    public function fetchCustomers($token)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        $whereClause = "business_id = '$businessId' AND deleted_at IS NULL";

        $this->selectQuery(
            "customers",
            "id, first_name, last_name, phone, country, state, street, status, created_at",
            $whereClause
        );

        if ($this->checkrow() > 0) {
            $customers = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $customers
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No customer found!"
            ];
        }
    }

    // LOGS ADD NEW SALES ORDER METHOD
    public function addNewSalesOrder($newOrderData, $table, $column, $token)
    {
        // Step 1: Resolve business ID
        $isJwt = strpos($token, '.') !== false; // simple check to distinguish JWT vs plain ID
        $businessId = $isJwt ? $this->getBusinessIdFromToken($token) : $token;

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid or missing business information"
            ];
        }

        // Step 2: Set and validate order type
        $orderType = 'sales';
        if (!in_array($orderType, ['sales', 'purchase'])) {
            return [
                "code" => "000",
                "message" => "Invalid order type"
            ];
        }

        $productId = $newOrderData["product_id"];
        $quantitySold = $newOrderData["quantity_sold"];
        $totalPrice = $newOrderData["total_price"];
        $discountPrice = $newOrderData["discount_price"] ?? 0;

        // Step 3: Get cost price of product
        $this->selectQuery(
            "products",
            "cost_price",
            "WHERE business_id = '$businessId' AND id = '$productId' AND deleted_at IS NULL"
        );

        if ($this->checkrow() > 0) {
            $productData = $this->fetchQuery();
            $cost_price = $productData[0]['cost_price'];
        } else {
            return ["code" => "000", "message" => "Problem getting product cost price"];
        }

        $profit = $totalPrice - ($cost_price * $quantitySold);

        // Step 4: Use supplied order ID or generate one
        $orderId = $newOrderData["order_id"] ?? $this->generateSequentialOrderId($orderType, $table);
        $timestamp = date('c');

        // Step 5: Prepare data for insert
        $orderRecord = [
            "business_id" => $businessId,
            "product_id" => $productId,
            "order_id" => $orderId,
            "customer_id" => $newOrderData["customer_id"] ?? null,
            "payment_status" => $newOrderData["payment_status"] ?? null,
            "unit_price" => $newOrderData["unit_price"] ?? null,
            "discount_price" => $discountPrice,
            "quantity_sold" => $quantitySold,
            "total_price" => $totalPrice,
            "amount_paid" => $newOrderData["amount_paid"] ?? null,
            "amount_remaining" => $newOrderData["amount_remaining"] ?? null,
            "profit" => $profit,
            "status" => Status::ACTIVE,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        $cleanData = $this->clean($orderRecord);

        // Step 6: Stock check
        $totalStock = $this->sumSelectQuery(
            "purchase_orders",
            "order_quantity",
            "WHERE business_id = ? AND product_id = ? AND deleted_at IS NULL",
            [$businessId, $productId]
        );

        $totalSold = $this->sumSelectQuery(
            "sales_orders",
            "quantity_sold",
            "WHERE business_id = ? AND product_id = ? AND deleted_at IS NULL",
            [$businessId, $productId]
        );

        $availableStock = (float) $totalStock - (float) $totalSold;

        if ($orderType === "sales" && $quantitySold > $availableStock) {
            return [
                "code" => "000",
                "message" => "Oops! Only {$availableStock} units left — please reduce quantity to proceed."
            ];
        }

        // Step 7: Insert order
        $insertSuccess = $this->insertQuery($table, $column, $cleanData);
        if (!$insertSuccess) {
            return ["code" => "000", "message" => "Oops! Problem adding order"];
        }

        // Step 8: Fetch inserted order for receipt
        $this->selectJoinQuery(
            "sales_orders",
            "business.name AS business,
         business.country AS business_country,
         business.state AS business_state,
         business.street AS business_street,
         products.name AS product,
         sales_orders.order_id,
         customers.first_name AS first_name,
         customers.last_name AS last_name,
         customers.country AS customer_country,
         customers.state AS customer_state,
         customers.street AS customer_street,
         customers.phone AS phone,
         sales_orders.payment_status,
         sales_orders.unit_price,
         sales_orders.quantity_sold,
         sales_orders.total_price,
         sales_orders.created_at",
            "JOIN business ON business.id = sales_orders.business_id
         JOIN products ON products.id = sales_orders.product_id
         JOIN customers ON customers.id = sales_orders.customer_id",
            "sales_orders.order_id = ? AND sales_orders.deleted_at IS NULL",
            [$orderId]
        );

        if ($this->checkrow() > 0) {
            return [
                "code" => "001",
                "message" => "Hurray! Order successfully added",
                "type" => $orderType,
                "data" => $this->fetchQuery()
            ];
        }

        return ["code" => "000", "message" => "Problem retrieving order data!"];
    }

    // LOGS UPDATE SALES ORDER METHOD
    public function updateSalesOrder($salesOrderData, $table, $column, $token)
    {
        // Step 1: Authenticate and get business ID
        $business_id = $this->getBusinessIdFromToken($token);

        if (!$business_id) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Sanitize and prepare update data
        $timestamp = date('c');
        $status = Status::ACTIVE;
         $productId = $salesOrderData["product_id"];
        $quantitySold = $salesOrderData["quantity_sold"];
        $totalPrice = $salesOrderData["total_price"];
        $discountPrice = $salesOrderData["discount_price"] ?? 0;

        // Step 3: Get cost price of product
        $this->selectQuery(
            "products",
            "cost_price",
            "WHERE business_id = '$business_id' AND id = '$productId' AND deleted_at IS NULL"
        );

        if ($this->checkrow() > 0) {
            $productData = $this->fetchQuery();
            $cost_price = $productData[0]['cost_price'];
        } else {
            return ["code" => "000", "message" => "Problem getting product cost price"];
        }

        $profit = $totalPrice - ($cost_price * $quantitySold);

        $updateData = [
            "business_id" => $business_id,
            "product_id" => $productId,
            "customer_id" => $salesOrderData["customer_id"] ?? null,
            "payment_status" => $salesOrderData["payment_status"] ?? null,
            "unit_price" => $salesOrderData["unit_price"] ?? null,
            "discount_price" => $discountPrice,
            "quantity_sold" => $quantitySold,
            "total_price" => $totalPrice,
            "amount_paid" => $salesOrderData["amount_paid"] ?? null,
            "amount_remaining" => $salesOrderData["amount_remaining"] ?? null,
            "profit" => $profit,
            "assigned_to" => $salesOrderData["assigned_to"] ?? null,
            "status" => Status::ACTIVE,
            "updated_at" => $timestamp
        ];
        $cleanData = $this->cleanUpdateData($updateData);

        // Step 3: Validate existence of the order by ID
        $checkSql = "SELECT $column FROM $table WHERE business_id = ? AND id = ?";
        $stmt = $this->conn_str->prepare($checkSql);
        $stmt->bind_param("ss", $business_id, $salesOrderData["id"]);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid order",
                "id" => $salesOrderData["id"],
            ];
        }


        // Step 5: Update the sales order
        $whereClause = "WHERE business_id = ? AND id = ?";
        $whereParams = [$business_id, $salesOrderData["id"]];

        $updated = $this->updateQuery($table, $cleanData, $whereClause, $whereParams);

        if ($updated) {
            return [
                "code" => "001",
                "message" => "Hurray! order successfully updated"
            ];
        } else {
            return [
                "code" => "000",
                "message" => "Oops! Problem updating order"
            ];
        }
    }


    // LOGS FETCH SALES ORDERS METHOD
    public function fetchSalesOrders($token)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        /*$whereClause = "business_id = '$businessId' AND deleted_at IS NULL";

        $this->selectQuery(
            "products",
            "id, name, category_id, price, quantity, stock_alert, supplier_id, vat, status, created_at",
            $whereClause
        );*/

        $this->selectJoinQuery(
            "sales_orders",
            "business.name AS business,
         business.country AS business_country,
         business.state AS business_state,
         business.street AS business_street,
         products.name AS product,
         sales_orders.id,
         sales_orders.order_id,
         customers.first_name AS first_name,
         customers.last_name AS last_name,
         customers.country AS customer_country,
         customers.state AS customer_state,
         customers.street AS customer_street,
         customers.phone AS phone,
         sales_orders.payment_status,
         sales_orders.unit_price,
         sales_orders.discount_price,
         sales_orders.quantity_sold,
         sales_orders.total_price,
         sales_orders.assigned_to,
         sales_orders.created_at",
            "JOIN business ON business.id = sales_orders.business_id
         JOIN products ON products.id = sales_orders.product_id
         JOIN customers ON customers.id = sales_orders.customer_id",
            "sales_orders.business_id = ? AND sales_orders.deleted_at IS NULL",
            [$businessId]
        );

        if ($this->checkrow() > 0) {
            $orders = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $orders
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No order found!"
            ];
        }
    }


    // LOGS ADD NEW PURCHASE ORDER METHOD
    public function addNewPurchaseOrder($newOrderData, $table, $column, $token)
    {
        // Step 1: Authenticate user and get business ID
        $businessId = $this->getBusinessIdFromToken($token);
        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Define and validate order type
        $orderType = 'purchase'; // Fixed for purchase order
        if (!in_array($orderType, ['sales', 'purchase'])) {
            return [
                "code" => "000",
                "message" => "Invalid order type"
            ];
        }

        // Step 3: Generate order ID and timestamp
        $orderId = $this->generateSequentialOrderId($orderType, $table);
        $timestamp = date('c');

        // Step 4: Construct order record
        $orderRecord = [
            "business_id" => $businessId,
            "product_id" => $newOrderData["product_id"] ?? null,
            "order_id" => $orderId,
            "supplier_id" => $newOrderData["supplier_id"] ?? null,
            "address_id" => $newOrderData["address_id"] ?? null,
            "delivery_status" => $newOrderData["delivery_status"] ?? null,
            "unit_cost" => $newOrderData["unit_cost"] ?? null,
            "order_quantity" => $newOrderData["order_quantity"] ?? null,
            "total_cost" => $newOrderData["total_cost"] ?? null,
            "status" => Status::ACTIVE,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        // Step 5: Clean the order data
        $cleanData = $this->clean($orderRecord);

        // Step 6: Insert the order into the database
        $insertSuccess = $this->insertQuery($table, $column, $cleanData);

        if (!$insertSuccess) {
            return [
                "code" => "000",
                "message" => "Oops! Problem adding order"
            ];
        }

        // Step 7: Fetch and return inserted order
        $this->selectJoinQuery(
            "purchase_orders",
            "business.name AS business,
         business.country AS business_country,
         business.state AS business_state,
         business.street AS business_street,
         products.name AS product,
         purchase_orders.order_id,
         suppliers.name AS supplier,
         suppliers.email AS email,
         suppliers.phone AS phone,
         purchase_orders.delivery_status,
         purchase_orders.unit_cost,
         purchase_orders.order_quantity,
         purchase_orders.total_cost,
         purchase_orders.created_at",
            "JOIN business ON business.id = purchase_orders.business_id
         JOIN products ON products.id = purchase_orders.product_id
         JOIN suppliers ON suppliers.id = purchase_orders.supplier_id",
            "purchase_orders.business_id = ? AND purchase_orders.deleted_at IS NULL",
            [$businessId]
        );

        if ($this->checkrow() > 0) {
            return [
                "code" => "001",
                "message" => "Hurray! Order successfully added",
                "type" => $orderType,
                "data" => $this->fetchQuery()
            ];
        }

        return [
            "code" => "000",
            "message" => "Problem retrieving order data!"
        ];
    }

    // LOGS FETCH PURCHASE ORDERS METHOD
    public function fetchPurchaseOrders($token)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        /*$whereClause = "business_id = '$businessId' AND deleted_at IS NULL";

        $this->selectQuery(
            "products",
            "id, name, category_id, price, quantity, stock_alert, supplier_id, vat, status, created_at",
            $whereClause
        );*/

        $this->selectJoinQuery(
            "purchase_orders",
            "business.name AS business,
         business.country AS business_country,
         business.state AS business_state,
         business.street AS business_street,
         products.name AS product,
         purchase_orders.order_id,
         suppliers.name AS supplier,
         suppliers.email AS email,
         suppliers.phone AS phone,
         address.country AS country,
         address.state AS state,
         address.street AS street,
         purchase_orders.delivery_status,
         purchase_orders.unit_cost,
         purchase_orders.order_quantity,
         purchase_orders.total_cost,
         purchase_orders.created_at",
            "JOIN business ON business.id = purchase_orders.business_id
         JOIN products ON products.id = purchase_orders.product_id
         JOIN suppliers ON suppliers.id = purchase_orders.supplier_id
         JOIN address ON address.id = purchase_orders.address_id",
            "purchase_orders.business_id = ? AND purchase_orders.deleted_at IS NULL",
            [$businessId]
        );

        if ($this->checkrow() > 0) {
            $orders = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $orders
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No order found!"
            ];
        }
    }




    /**
     * Summary of addNewTransfer
     * @param mixed $newTransferData
     * @param mixed $table
     * @param mixed $column
     * @param mixed $token
     * @return array{code: int|string, message: string}
     */
    public function addNewTransfer($newTransferData, $table, $column, $token)
    {
        // Step 1: Authenticate and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($token);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Generate a unique customer_id in the format "C_XXXXXX"
        // $customerId = $this->generateUniqueCustomerId($table);

        // Step 3: Build customer record
        $timestamp = date('c');
        $transferRecord = [
            "business_id" => $businessId,
            "product_id" => $newTransferData["product_id"],
            "transfer_status" => $newTransferData["transfer_status"],
            "quantity" => $newTransferData["quantity"],
            "from_address_id" => $newTransferData["from_address_id"],
            "to_address_id" => $newTransferData["to_address_id"],
            "assigned_to" => $newTransferData["assigned_to"],
            "status" => Status::ACTIVE,
            "created_at" => $timestamp,
            "updated_at" => $timestamp
        ];

        // Step 4: Clean data
        $cleanData = $this->clean($transferRecord);

        // Step 6: Check available stock
        /*$productId = $cleanData[1]; // Assumes product_id is 2nd in order of columns
        $quantityRequested = $cleanData[3]; // Assumes quantity_sold is 4th
        $fromAddress =  $cleanData[4];

        $totalStock = $this->sumSelectQuery(
            "products",
            "quantity",
            "WHERE business_id = ? AND id = ? AND address_id = ? AND deleted_at IS NULL",
            [$businessId, $productId, $fromAddress]
        );

        $totalSold = $this->sumSelectQuery(
            "sales_orders",
            "quantity_sold",
            "WHERE business_id = ? AND product_id = ? AND deleted_at IS NULL",
            [$businessId, $productId]
        );

        $availableStock = (float) $totalStock - (float) $totalSold;

        if ($quantityRequested > $availableStock) {
            return [
                "code" => "000",
                "message" => "Oops! Only {$availableStock} units left — please reduce quantity to proceed."
            ];
        }*/
        // Step 6: Insert new customer
        $inserted = $this->insertQuery($table, $column, $cleanData);

        if (!$inserted) {
            return [
                "code" => "000",
                "message" => "Oops! Problem adding transfer"
            ];
        }

        return [
            "code" => "001",
            "message" => "Hurray! Transfer successfully added"
        ];
    }

    // LOGS FETCH TRANSFERS METHOD
    public function fetchTransfers($businessIDToken)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($businessIDToken);

        if (!$businessId) {
            return [
                "code" => "000",
                "message" => "Oops! Invalid user"
            ];
        }

        // Step 2: Define selected columns
        $columns = "
        t.id AS transfer_id,
        p.name AS product,
        t.transfer_status AS transfer_status,
        t.quantity AS quantity,

        from_addr.street AS from_street,
        from_addr.state AS from_state,
        from_addr.country AS from_country,

        to_addr.street AS to_street,
        to_addr.state AS to_state,
        to_addr.country AS to_country,

        u.username AS assigned_to,
        t.created_at AS created_at
    ";

        // Step 3: Define JOINs (manual string)
        $joins = "
        JOIN products AS p ON p.id = t.product_id
        JOIN address AS from_addr ON from_addr.id = t.from_address_id
        JOIN address AS to_addr ON to_addr.id = t.to_address_id
        JOIN users AS u ON u.id = t.assigned_to
    ";

        // Step 4: Call the selectJoinQuery
        $this->selectJoinQuery(
            "transfers AS t",
            $columns,
            $joins,
            "t.business_id = ? AND t.deleted_at IS NULL",
            [$businessId]
        );

        // Step 5: Return result
        if ($this->checkrow() > 0) {
            $transfers = $this->fetchQuery();
            return [
                "code" => "001",
                "message" => $transfers
            ];
        } else {
            return [
                "code" => "000",
                "message" => "No transfers found!"
            ];
        }
    }


    // LOGS FETCH ORDERS METHOD
    public function fetchOrders($businessIDToken)
    {
        $decodedbusinessIDToken = $this->getId($businessIDToken);
        $this->selectQuery("logsinv1_u739192517_Order_Table", "productName as pN, orderType as oT, orderID as oID, orderQuantity as oQ, reorderPoint as rP, orderStatus as oS, addedOn as aO", "WHERE businessName = '$decodedbusinessIDToken' AND status = '1'");

        if ($this->checkrow() > 0) {
            $orders = $this->fetchQuery();
            return array("code" => "001", "message" => $orders);
        } else {
            return array("code" => "000", "message" => "No product found!");
        }
    }

    // LOGS FETCH PURCHASES METHOD
    public function fetchPurchases($businessIDToken)
    {
    }

    // LOGS GET INVENTORY VALUE DATA METHOD
    public function getInventoryValue($businessIDToken)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($businessIDToken);

        if (!$businessId) {
            return $this->response("000", "Oops! Invalid user");
        }

        // Step 2: Calculate total inventory value
        $totalPurchaseValue = $this->sumSelectQuery(
            "purchase_orders",
            "total_cost",
            "WHERE business_id = ? AND deleted_at IS NULL",
            [$businessId]
        );

        $inventoryValue = $totalPurchaseValue;

        // Step 3: Return formatted response
        return $this->response("001", $inventoryValue);
    }

    // LOGS GET INVENTORY PROFIT DATA METHOD
    public function getInventoryProfit($businessIDToken)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($businessIDToken);

        if (!$businessId) {
            return $this->response("000", "Oops! Invalid user");
        }

        // Step 2: Calculate total inventory value
        $totalProfitValue = $this->sumSelectQuery(
            "sales_orders",
            "profit",
            "WHERE business_id = ? AND payment_status = ? AND deleted_at IS NULL",
            [$businessId, "paid"]
        );


        // Step 3: Return formatted response
        return $this->response("001", $totalProfitValue);
    }

    /**
     * Helper method for consistent response format
     */
    private function response($code, $message)
    {
        return [
            "code" => $code,
            "message" => $message
        ];
    }


    // LOGS GET INVENTORY PRODUCTS COUNT DATA METHOD
    public function getProductsCount($businessIDToken)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($businessIDToken);

        if (!$businessId) {
            return $this->response("000", "Oops! Invalid user");
        }

        $this->selectQuery("products", "name", "WHERE businessName = '$businessId' AND status = '01'");

        if ($this->checkrow() > 0) {
            $productsCount = $this->checkrow();
            return array("code" => "001", "message" => $productsCount);
        } else {
            $productsCount = 0;
            return array("code" => "000", "message" => $productsCount);
        }
    }

    // LOGS GET INVENTORY ORDERS COUNT DATA METHOD
    public function getOrdersCount($businessIDToken)
    {
        // Step 1: Authenticate user and retrieve business ID
        $businessId = $this->getBusinessIdFromToken($businessIDToken);

        if (!$businessId) {
            return $this->response("000", "Oops! Invalid user");
        }

        $this->selectQuery("sales_orders", "order_id", "WHERE business_id = '$businessId' AND deleted_at IS NULL");

        if ($this->checkrow() > 0) {
            $ordersCount = $this->checkrow();
            return array("code" => "001", "message" => $ordersCount);
        } else {
            $ordersCount = 0;
            return array("code" => "000", "message" => $ordersCount);
        }
    }

    // LOGS UPDATE METHOD
    public function updateRecord($data, $table, $fields, $token, $whereKey = 'id')
    {
        $conn = $this->connect();
        if (!$conn) {
            return ["code" => "002", "message" => "Database connection failed"];
        }

        // Optionally fetch business_id from token (if required for the table)
        $businessId = $this->getBusinessIdFromToken($token);
        if (!$businessId && in_array('business_id', explode(',', $fields))) {
            return ["code" => "002", "message" => "Invalid or missing business token"];
        }

        // Prepare SET clause
        $fieldList = explode(",", $fields);
        $setParts = [];
        $params = [];
        $types = "";

        foreach ($fieldList as $field) {
            $field = trim($field);

            if ($field === 'updated_at') {
                $setParts[] = "updated_at = NOW()";
                continue;
            }

            if ($field === 'business_id') {
                $setParts[] = "business_id = ?";
                $params[] = $businessId;
                $types .= "i";
                continue;
            }

            // Only include fields present in $data
            if (array_key_exists($field, $data)) {
                $setParts[] = "$field = ?";
                $params[] = $data[$field];
                $types .= is_numeric($data[$field]) ? "d" : "s";
            }
        }

        // WHERE clause (default: id)
        if (!isset($data[$whereKey])) {
            return ["code" => "002", "message" => ucfirst($whereKey) . " is required"];
        }

        $sql = "UPDATE `$table` SET " . implode(", ", $setParts) . " WHERE `$whereKey` = ?";
        $params[] = $data[$whereKey];
        $types .= is_numeric($data[$whereKey]) ? "i" : "s";

        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            return ["code" => "002", "message" => "SQL error: " . $conn->error];
        }

        $stmt->bind_param($types, ...$params);

        if ($stmt->execute()) {
            return ["code" => "001", "message" => ucfirst($table) . " updated successfully"];
        } else {
            return ["code" => "002", "message" => "Update failed: " . $stmt->error];
        }
    }

}

?>