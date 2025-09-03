const express = require('express');
const router = express.Router();

const { authenticate } = require('../middleware/authMiddleware');
const { authorizeRoles } = require('../middleware/roleMiddleware');
const { register, login, getUsers, updateUser, forgotPassword, resetPassword, deactivateUser, updateRole } = require('../controllers/authController');

//  Authentication
router.route("/register").post(register);
router.route("/login").post(login);

//  User Management

router.route("/")
  .get(authenticate, authorizeRoles("super_admin", "branch_manager"), getUsers);


router.route("/:id")
  .put(authenticate, authorizeRoles("super_admin", "branch_manager"), updateUser);


router.route("/:id/deactivate")
  .put(authenticate, authorizeRoles("super_admin"), deactivateUser);

router.route("/:id")
  .put(authenticate,authorizeRoles("super_admin", "admin"),updateRole);


router.route('/forgot-password').post(forgotPassword);
router.route('/reset-password/:token').post(resetPassword);


module.exports = router;
