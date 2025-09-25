<?php
class HandleSql
{
    public $conn_str;
    public $select;

    public function __construct($host, $username, $password, $dbname)
    {
        $this->conn_str = new mysqli($host, $username, $password, $dbname);
        if ($this->conn_str->connect_error) {
            die("Connection failed: " . $this->conn_str->connect_error);
        }
    }

    public function selectQuery(string $table, string $columns, string $where = '', array $params = []): void
    {
        // Basic validation to allow only letters, numbers, underscores, commas, spaces in table/columns
        if (!preg_match('/^[a-zA-Z0-9_,\s]+$/', $table)) {
            throw new InvalidArgumentException("Invalid table name");
        }
        if (!preg_match('/^[a-zA-Z0-9_,\s]+$/', $columns)) {
            throw new InvalidArgumentException("Invalid columns");
        }

        // Add WHERE keyword if needed
        $whereClause = '';
        if ($where !== '') {
            $where = trim($where);
            if (stripos($where, 'where') !== 0) {
                $whereClause = " WHERE $where";
            } else {
                $whereClause = " $where";
            }
        }

        $sql = "SELECT $columns FROM $table" . $whereClause;

        $stmt = $this->conn_str->prepare($sql);
        if (!$stmt) {
            throw new RuntimeException("Prepare failed: " . $this->conn_str->error);
        }

        if (!empty($params)) {
            $types = str_repeat('s', count($params));
            $stmt->bind_param($types, ...$params);
        }

        if (!$stmt->execute()) {
            throw new RuntimeException("Execute failed: " . $stmt->error);
        }

        $this->select = $stmt->get_result();
        $stmt->close();
    }

    public function selectJoinQuery($table, $columns, $joins = '', $where = '', $params = [])
    {
        $sql = "SELECT $columns FROM $table";

        if (!empty($joins)) {
            $sql .= " $joins";
        }

        if (!empty($where)) {
            $sql .= " WHERE $where";
        }

        $stmt = $this->conn_str->prepare($sql);
        if (!$stmt) {
            die("Prepare failed: " . $this->conn_str->error);
        }

        if (!empty($params)) {
            $types = str_repeat('s', count($params)); // consider using type inference later
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $this->select = $stmt->get_result();
        $stmt->close();
    }

    public function sumSelectQuery($table, $expression, $where = '', $params = [])
    {
        // Sanitize column/expression manually (caller must ensure it's valid)
        $sql = "SELECT SUM($expression) AS sumOutput FROM `$table` $where";
        $stmt = $this->conn_str->prepare($sql);

        if (!$stmt) {
            die("Prepare failed: " . $this->conn_str->error);
        }

        if (!empty($params)) {
            $types = str_repeat('s', count($params)); // Adjust type based on expected param type
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        return $result['sumOutput'] ?? 0;
    }

    public function insertQuery($table, $columns, $dataArray)
    {
        $columnArray = explode(",", str_replace(" ", "", $columns));
        if (count($columnArray) !== count($dataArray)) {
            error_log("Column/Data mismatch: " . count($columnArray) . " columns, " . count($dataArray) . " values.");
            error_log("Columns: " . implode(",", $columnArray));
            error_log("Data: " . json_encode($dataArray));
            return false;
        }

        $placeholders = implode(",", array_fill(0, count($dataArray), "?"));
        $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
        $stmt = $this->conn_str->prepare($sql);
        if (!$stmt) {
            error_log("Prepare failed: " . $this->conn_str->error);
            return false;
        }

        $types = '';
        foreach ($dataArray as $value) {
            if (is_int($value)) {
                $types .= 'i';
            } elseif (is_float($value)) {
                $types .= 'd';
            } else {
                $types .= 's';
            }
        }

        $stmt->bind_param($types, ...$dataArray);

        $result = $stmt->execute();
        if (!$result) {
            error_log("Insert execution failed: " . $stmt->error);
        }

        $stmt->close();
        return $result;
    }


    public function updateQuery($table, $data, $whereClause, $whereParams)
    {
        $setParts = [];
        $values = [];
        foreach ($data as $key => $value) {
            $setParts[] = "$key = ?";
            $values[] = $value;
        }
        foreach ($whereParams as $param) {
            $values[] = $param;
        }

        $types = str_repeat('s', count($values));
        $setString = implode(", ", $setParts);
        $sql = "UPDATE $table SET $setString $whereClause";

        $stmt = $this->conn_str->prepare($sql);
        if (!$stmt)
            die("Prepare failed: " . $this->conn_str->error);
        $stmt->bind_param($types, ...$values);

        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }

    public function deleteQuery($table, $whereClause, $params = [])
    {
        $sql = "DELETE FROM $table $whereClause";
        $stmt = $this->conn_str->prepare($sql);
        if (!$stmt)
            die("Prepare failed: " . $this->conn_str->error);

        if (!empty($params)) {
            $types = str_repeat("s", count($params));
            $stmt->bind_param($types, ...$params);
        }

        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }

    public function fetchQuery()
    {
        $bag = [];
        while ($row = $this->select->fetch_assoc()) {
            $bag[] = $row;
        }
        return $bag;
    }

    /**
     * Hashes password using password_hash (bcrypt)
     */
    public function hash_password($plainPassword)
    {
        return password_hash($plainPassword, PASSWORD_BCRYPT);
    }

    /**
     * Verifies a plaintext password against a hashed one
     */
    public function verify_password($plainPassword, $hashedPassword)
    {
        return password_verify($plainPassword, $hashedPassword);
    }

    public function clean($dirty)
    {
        $cleaned_output = [];
        foreach ($dirty as $key => $value) {
            if (in_array($key, ["password", "newpassword"])) {
                if (!empty($value)) {
                    $value = $this->hash_password($value);
                }
            }
            $cleaned_output[] = $this->conn_str->real_escape_string($value);
        }
        return $cleaned_output;
    }

    public function cleanUpdateData($dirty)
    {
        $cleaned_output = [];
        foreach ($dirty as $key => $value) {
            if (in_array($key, ["password", "newpassword"])) {
                if (!empty($value)) {
                    $value = $this->hash_password($value);
                }
            }
            $cleaned_output[$key] = $this->conn_str->real_escape_string($value);
        }
        return $cleaned_output;
    }

    public function checkrow()
    {
        return $this->select ? $this->select->num_rows : 0;
    }

    public function addquote($receive)
    {
        return array_map(fn($val) => "'$val'", $receive);
    }

    public function convertMeToString($glue, $arr)
    {
        return implode($glue, $arr);
    }

    public function randomString($limit)
    {
        return substr(base_convert(sha1(uniqid(mt_rand(), true)), 16, 36), 0, $limit);
    }
}
?>