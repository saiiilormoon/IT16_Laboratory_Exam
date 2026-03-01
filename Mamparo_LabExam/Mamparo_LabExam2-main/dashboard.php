<?php
// ============================================
// SECURE DASHBOARD
// Fixes: Access control, session timeout,
// XSS output escaping, prepared statements
// ============================================

// Secure session cookie settings (MUST be before session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);

session_start();

include("db.php");
include("csrf.php");
include("security_headers.php");

// --- FIX: Access Control - Redirect if not logged in ---
if (!isset($_SESSION['user']) || !isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit(); // FIX: exit() after redirect
}

// --- FIX: Session Timeout (30 minutes) ---
$timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
    session_unset();
    session_destroy();
    header("Location: login.php?timeout=1");
    exit();
}
$_SESSION['last_activity'] = time();

// --- Handle Delete (POST method with CSRF, admin only) ---
$msg = "";
$add_error = "";
if (isset($_POST['delete_student'])) {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $msg = "Invalid request.";
    } elseif ($_SESSION['role'] !== 'admin') {
        $msg = "Access denied. Admin only.";
    } else {
        $delete_id = intval($_POST['student_id'] ?? 0);
        if ($delete_id > 0) {
            $del_stmt = $conn->prepare("DELETE FROM students WHERE id = ?");
            $del_stmt->bind_param("i", $delete_id);
            $del_stmt->execute();
            $del_stmt->close();
            $msg = "Student deleted successfully.";
        }
    }
    unset($_SESSION['csrf_token']);
}

// --- Handle Add Student (POST from modal) ---
$show_add_modal = false;
if (isset($_POST['add'])) {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $add_error = "Invalid request. Please try again.";
        $show_add_modal = true;
    } else {
        $student_id = trim($_POST['student_id'] ?? '');
        $fullname   = trim($_POST['fullname'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $course_id  = intval($_POST['course_id'] ?? 0);

        if (empty($student_id) || empty($fullname) || empty($email)) {
            $add_error = "Please fill in all required fields.";
            $show_add_modal = true;
        } elseif (strlen($student_id) > 50) {
            $add_error = "Student ID is too long (max 50 characters).";
            $show_add_modal = true;
        } elseif (strlen($fullname) > 100) {
            $add_error = "Full name is too long (max 100 characters).";
            $show_add_modal = true;
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $add_error = "Please enter a valid email address.";
            $show_add_modal = true;
        } elseif ($course_id <= 0) {
            $add_error = "Please select a course.";
            $show_add_modal = true;
        } else {
            $check_stmt = $conn->prepare("SELECT id FROM students WHERE student_id = ?");
            $check_stmt->bind_param("s", $student_id);
            $check_stmt->execute();
            if ($check_stmt->get_result()->num_rows > 0) {
                $add_error = "Student ID already exists.";
                $show_add_modal = true;
            } else {
                $stmt = $conn->prepare("INSERT INTO students (student_id, fullname, email, course_id, created_by) VALUES (?, ?, ?, ?, ?)");
                $created_by = $_SESSION['user_id'];
                $stmt->bind_param("sssii", $student_id, $fullname, $email, $course_id, $created_by);
                if ($stmt->execute()) {
                    $msg = "Student added successfully!";
                } else {
                    $add_error = "Failed to add student. Please try again.";
                    $show_add_modal = true;
                }
                $stmt->close();
            }
            $check_stmt->close();
        }
    }
    unset($_SESSION['csrf_token']);
}

// Fetch courses for modal dropdown
$courses_result = $conn->query("SELECT id, course_code, course_description FROM courses ORDER BY course_code");
$courses = [];
while ($cat = $courses_result->fetch_assoc()) {
    $courses[] = $cat;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard — Student Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="style.css?v=2.2">
</head>
<body>

<div class="container-wide">

    <div class="top-bar">
        <div>
            <h2><i class="fa-solid fa-hand-wave"></i> Welcome, <?php echo htmlspecialchars($_SESSION['user'], ENT_QUOTES, 'UTF-8'); ?>
                <span class="role-badge"><?php echo htmlspecialchars($_SESSION['role'], ENT_QUOTES, 'UTF-8'); ?></span>
            </h2>
        </div>
        <div class="nav-links">
            <a href="#" onclick="openAddModal(); return false;"><i class="fa-solid fa-user-plus"></i> Add Student</a>
            <?php if ($_SESSION['role'] === 'admin'): ?>
                <a href="backup.php"><i class="fa-solid fa-database"></i> Backup</a>
            <?php endif; ?>
            <a href="logout.php" class="btn-logout"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
        </div>
    </div>

    <?php if (!empty($msg)): ?>
        <p class="success"><?php echo htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>

    <?php
    // --- FIX: Use JOIN for normalized data (courses table) ---
    $query = "SELECT s.id, s.student_id, s.fullname, s.email, 
                     c.course_code, c.course_description
              FROM students s
              LEFT JOIN courses c ON s.course_id = c.id
              ORDER BY s.id ASC";
    $result = $conn->query($query);
    $student_count = $result ? $result->num_rows : 0;
    ?>

    <div class="stats-row">
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-graduation-cap"></i></div>
            <div class="stat-value"><?php echo $student_count; ?></div>
            <div class="stat-label">Total Students</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-user-shield"></i></div>
            <div class="stat-value"><?php echo htmlspecialchars($_SESSION['role'], ENT_QUOTES, 'UTF-8'); ?></div>
            <div class="stat-label">Your Role</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-shield-halved"></i></div>
            <div class="stat-value">Active</div>
            <div class="stat-label">Session Status</div>
        </div>
    </div>

    <div class="card">
    <h3><i class="fa-solid fa-list"></i> Student List</h3>

    <div class="table-wrapper">
    <table>
    <tr>
        <th>ID</th>
        <th>Student ID</th>
        <th>Full Name</th>
        <th>Email</th>
        <th>Course</th>
        <th>Description</th>
        <?php if ($_SESSION['role'] === 'admin'): ?>
            <th style="width:90px;">Action</th>
        <?php endif; ?>
    </tr>

    <?php
    if ($result && $student_count > 0):
        while ($row = $result->fetch_assoc()):
    ?>
    <tr>
        <!-- FIX: All output escaped with htmlspecialchars -->
        <td><?php echo intval($row['id']); ?></td>
        <td><?php echo htmlspecialchars($row['student_id'], ENT_QUOTES, 'UTF-8'); ?></td>
        <td><?php echo htmlspecialchars($row['fullname'], ENT_QUOTES, 'UTF-8'); ?></td>
        <td><?php echo htmlspecialchars($row['email'], ENT_QUOTES, 'UTF-8'); ?></td>
        <td><?php echo htmlspecialchars($row['course_code'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
        <td><?php echo htmlspecialchars($row['course_description'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
        <?php if ($_SESSION['role'] === 'admin'): ?>
            <td>
                <!-- FIX: Delete via POST with CSRF (prevents direct object reference) -->
                <form method="POST" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete this student?');">
                    <?php csrf_input(); ?>
                    <input type="hidden" name="student_id" value="<?php echo intval($row['id']); ?>">
                    <button type="submit" name="delete_student" class="btn-delete"><i class="fa-solid fa-trash"></i> Delete</button>
                </form>
            </td>
        <?php endif; ?>
    </tr>
    <?php
        endwhile;
    else:
    ?>
    <tr><td colspan="7" class="no-data">
        <i class="fa-solid fa-folder-open" style="font-size:32px;color:#cbd5e1;display:block;margin-bottom:10px;"></i>
        No students found. <a href="#" onclick="openAddModal(); return false;">Add your first student</a>
    </td></tr>
    <?php endif; ?>

    </table>
    </div>
    </div>
</div>

<!-- Add Student Modal -->
<div class="modal-overlay" id="addStudentModal">
    <div class="modal-box modal-form">
        <div class="modal-header">
            <h3><i class="fa-solid fa-user-plus"></i> Add New Student</h3>
            <button type="button" class="modal-close" onclick="closeAddModal()">
                <i class="fa-solid fa-xmark"></i>
            </button>
        </div>
        <div class="modal-body">
            <?php if (!empty($add_error)): ?>
                <p class="error"><?php echo htmlspecialchars($add_error, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <form method="POST" action="dashboard.php" id="addStudentForm">
                <?php csrf_input(); ?>

                <div class="form-group">
                    <label><i class="fa-solid fa-id-card"></i> Student ID</label>
                    <input type="text" name="student_id" placeholder="e.g., 2024-0001"
                           value="<?php echo htmlspecialchars($_POST['student_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="50">
                </div>

                <div class="form-group">
                    <label><i class="fa-solid fa-user"></i> Full Name</label>
                    <input type="text" name="fullname" placeholder="Enter full name"
                           value="<?php echo htmlspecialchars($_POST['fullname'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="100">
                </div>

                <div class="form-group">
                    <label><i class="fa-solid fa-envelope"></i> Email Address</label>
                    <input type="email" name="email" placeholder="Enter email address"
                           value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="100">
                </div>

                <div class="form-group">
                    <label><i class="fa-solid fa-book"></i> Course</label>
                    <select name="course_id" required>
                        <option value="">-- Select Course --</option>
                        <?php foreach ($courses as $course): ?>
                            <option value="<?php echo intval($course['id']); ?>"
                                <?php echo (intval($_POST['course_id'] ?? 0) === intval($course['id'])) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($course['course_code'] . ' - ' . $course['course_description'], ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="modal-actions">
                    <button type="button" class="modal-btn modal-btn-cancel" onclick="closeAddModal()"><i class="fa-solid fa-xmark"></i> Cancel</button>
                    <button type="submit" name="add" class="modal-btn modal-btn-confirm"><i class="fa-solid fa-plus"></i> Add Student</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function openAddModal() {
    document.getElementById('addStudentModal').classList.add('active');
    document.body.style.overflow = 'hidden';
    // Focus the first input after animation
    setTimeout(function() {
        var firstInput = document.querySelector('#addStudentForm input[name="student_id"]');
        if (firstInput) firstInput.focus();
    }, 350);
}

function closeAddModal() {
    document.getElementById('addStudentModal').classList.remove('active');
    document.body.style.overflow = '';
}

// Close on overlay click (not on modal box itself)
document.getElementById('addStudentModal').addEventListener('click', function(e) {
    if (e.target === this) closeAddModal();
});

// Close on Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeAddModal();
});

// Auto-open modal if there was a validation error
<?php if ($show_add_modal): ?>
openAddModal();
<?php endif; ?>
</script>

</body>
</html>
