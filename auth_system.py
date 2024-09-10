import os, sys, redis, hashlib, uuid, pytest, pandas as pd
from redis.exceptions import ConnectionError, RedisError
from dotenv import load_dotenv
from PyQt5.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

"""
README - Important!!!

To run this application, you will need to install a few required libraries.

Run the following command in the terminal to install the necessary libraries:
pip install redis PyQt5 pytest pandas
"""

# Load environment variables from .env file
load_dotenv()

# Fetch the Redis credentials from environment variables
redis_host = os.getenv("REDIS_HOST")
redis_port = os.getenv("REDIS_PORT")
redis_password = os.getenv("REDIS_PASSWORD")

try:
    # Create a connection to Redis using credentials from the .env file
    redisConnection = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password,
        decode_responses=True,
    )
except ConnectionError as e:
    print(f"Failed to connect to Redis: {e}")

"""
This class is responsible for creating the application's GUI and managing the logic for
data validation and database operations.
"""


class AppWindow(QWidget):
    def __init__(self):
        """
        Initializes the main window of the 'Find a Campsite' application.

        This constructor sets the window title, creates and initializes the necessary pages,
        and the reset password pages, and adds them to a stacked widget. The stacked widget
        allows for easy navigation between different pages of the app. Finally, it sets up
        the overall layout of the app and displays the pages.

        Pages initialized:
            - Login Page
            - Registration Page
            - Reset Password Page (1/3)
            - Security Question Page (2/3)
            - Set New Password Page (3/3)
        """
        super().__init__()

        self.setWindowTitle("Find a Campsite")  # Set the title of the window

        self.stacked_widget = (
            QStackedWidget()
        )  # Create a stacked widget to handle multiple pages

        # Initialise the pages the app needs
        self.registerPage = self.RegisterPage()
        self.loginPage = self.LoginPage()
        self.resetPasswordPage = self.ResetPasswordPage()
        self.securityQuestionPage = self.SecurityQuestionPage()
        self.setNewPasswordPage = self.SetNewPasswordPage()

        # Add the pages to the stacked widget
        self.stacked_widget.addWidget(self.loginPage)
        self.stacked_widget.addWidget(self.registerPage)
        self.stacked_widget.addWidget(self.resetPasswordPage)
        self.stacked_widget.addWidget(self.securityQuestionPage)
        self.stacked_widget.addWidget(self.setNewPasswordPage)

        # Create a layout for the app window and add the stacked widget to it
        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

    def RegisterPage(self):
        """
        Creates the Registration Page
        This includes all the inputs that are required by the users, (First Name, Email, Password,
        Confirm Password, Security Question, Security Answer), and buttons for submitting the
        registration form and navigating to the login page.
        """
        registerPage = QWidget()
        registrationForm = QFormLayout()

        self.registrationFirstNameInput = QLineEdit()
        registrationForm.addRow(QLabel("First Name:"), self.registrationFirstNameInput)

        self.registrationEmailInput = QLineEdit()
        registrationForm.addRow(QLabel("Email:"), self.registrationEmailInput)

        self.registrationPasswordInput = QLineEdit()
        self.registrationPasswordInput.setEchoMode(QLineEdit.Password)
        registrationForm.addRow(QLabel("Password:"), self.registrationPasswordInput)

        self.registrationConfirmPasswordInput = QLineEdit()
        self.registrationConfirmPasswordInput.setEchoMode(QLineEdit.Password)
        registrationForm.addRow(
            QLabel("Confirm Password:"), self.registrationConfirmPasswordInput
        )

        self.defaultQuestionButton = QRadioButton("Default Question")
        self.customQuestionButton = QRadioButton("Custom Question")

        self.buttonGroup = QButtonGroup()
        self.buttonGroup.addButton(self.defaultQuestionButton)
        self.buttonGroup.addButton(self.customQuestionButton)

        registrationForm.addWidget(self.defaultQuestionButton)
        registrationForm.addWidget(self.customQuestionButton)

        self.registrationSecurityQuestionInput = QLineEdit()
        registrationForm.addRow(
            QLabel("Security Question:"), self.registrationSecurityQuestionInput
        )

        self.registrationSecurityAnswerInput = QLineEdit()
        registrationForm.addRow(
            QLabel("Security Answer:"), self.registrationSecurityAnswerInput
        )

        self.defaultQuestionButton.toggle()
        self.HandleSecurityQuestionType("Default")

        self.defaultQuestionButton.toggled.connect(
            lambda: self.HandleSecurityQuestionType("Default")
        )
        self.customQuestionButton.toggled.connect(
            lambda: self.HandleSecurityQuestionType("Custom")
        )

        self.messageLabelRegistration = QLabel("")
        self.messageLabelRegistration.setVisible(False)
        registrationForm.addWidget(self.messageLabelRegistration)

        self.createAccountButton = QPushButton("Create Account")
        self.createAccountButton.clicked.connect(
            lambda: self.HandleRegistrationFormValidation()
        )

        registrationForm.addWidget(self.createAccountButton)

        loginNavButton = QPushButton("Login")
        loginNavButton.clicked.connect(lambda: self.HandleNavigation(0))
        registrationForm.addRow(QLabel("Already have an account?"), loginNavButton)
        registerPage.setLayout(registrationForm)
        return registerPage

    def LoginPage(self):
        """
        Creates the Login Page.
        Includes input fields for email and password, and buttons for logging in and
        navigating to other pages like 'Forgot Password' or 'Create Account.'
        """
        loginPage = QWidget()
        loginForm = QFormLayout()

        self.loginEmailInput = QLineEdit()
        loginForm.addRow(QLabel("Email:"), self.loginEmailInput)

        self.loginPasswordInput = QLineEdit()
        self.loginPasswordInput.setEchoMode(QLineEdit.Password)
        loginForm.addRow(QLabel("Password:"), self.loginPasswordInput)

        self.messageLabelLogin = QLabel("")
        self.messageLabelLogin.setVisible(False)  # Initially hide the label
        loginForm.addWidget(self.messageLabelLogin)

        self.loginButton = QPushButton("Login")
        self.loginButton.clicked.connect(lambda: self.HandleLoginFormValidation())
        loginForm.addWidget(self.loginButton)

        resetPasswordNavButton = QPushButton("Forgot Password?")
        resetPasswordNavButton.clicked.connect(lambda: self.HandleNavigation(2))
        loginForm.addWidget(resetPasswordNavButton)

        registrationNavButton = QPushButton("Create Account")
        registrationNavButton.clicked.connect(lambda: self.HandleNavigation(1))
        loginForm.addRow(QLabel("Don't have an account?"), registrationNavButton)

        loginPage.setLayout(loginForm)
        return loginPage

    def ResetPasswordPage(self):
        """
        Creates the Reset Password Page (1/3)
        Includes input for the user's email and a 'Next' button to proceed with password reset.
        """
        resetPasswordPage = QWidget()
        resetPasswordForm = QFormLayout()

        self.resetPasswordEmailInput = QLineEdit()
        resetPasswordForm.addRow(QLabel("Email:"), self.resetPasswordEmailInput)

        self.messageLabelResetPassword = QLabel("")
        self.messageLabelResetPassword.setVisible(False)
        resetPasswordForm.addWidget(self.messageLabelResetPassword)

        securityQuestionNavButton = QPushButton("Next")
        securityQuestionNavButton.clicked.connect(lambda: self.ValidateEmail())
        resetPasswordForm.addWidget(securityQuestionNavButton)

        resetPasswordPage.setLayout(resetPasswordForm)
        return resetPasswordPage

    def SecurityQuestionPage(self):
        """
        Creates the Security Question Page (2/3)
        This page displays the security question associated with the provided email.
        The user must enter the correct answer to proceed.
        """
        securityQuestionPage = QWidget()
        securityQuestionForm = QFormLayout()

        self.securityQuestionLabel = QLabel("")

        securityQuestionForm.addRow(
            QLabel("Security Question:"),
            self.securityQuestionLabel,
        )

        self.securityAnswerInput = QLineEdit()
        securityQuestionForm.addRow(
            QLabel("Security Answer:"), self.securityAnswerInput
        )

        self.messageLabelSecurityQuestion = QLabel("")
        self.messageLabelSecurityQuestion.setVisible(False)
        securityQuestionForm.addWidget(self.messageLabelSecurityQuestion)

        setNewPasswordNavButton = QPushButton("Next")
        setNewPasswordNavButton.clicked.connect(lambda: self.ValidateSecurityQnA())
        securityQuestionForm.addWidget(setNewPasswordNavButton)

        securityQuestionPage.setLayout(securityQuestionForm)
        return securityQuestionPage

    def SetNewPasswordPage(self):
        """
        Creates the Set New Password Page (3/3)
        This page allows the user to enter a new password and save the password.
        """
        setNewPasswordPage = QWidget()
        setNewPasswordForm = QFormLayout()

        self.newPasswordInput = QLineEdit()
        self.newPasswordInput.setEchoMode(QLineEdit.Password)
        setNewPasswordForm.addRow(QLabel("New Password:"), self.newPasswordInput)

        self.confirmNewPasswordInput = QLineEdit()
        self.confirmNewPasswordInput.setEchoMode(QLineEdit.Password)
        setNewPasswordForm.addRow(
            QLabel("Confirm Password:"), self.confirmNewPasswordInput
        )

        self.messageLabelSetNewPassword = QLabel("")
        self.messageLabelSetNewPassword.setVisible(False)
        setNewPasswordForm.addWidget(self.messageLabelSetNewPassword)

        self.setNewPasswordButton = QPushButton("Set New Password")
        self.setNewPasswordButton.clicked.connect(lambda: self.ValidateNewPassword())
        setNewPasswordForm.addWidget(self.setNewPasswordButton)

        setNewPasswordPage.setLayout(setNewPasswordForm)
        return setNewPasswordPage

    # Handles navigation between pages
    def HandleNavigation(self, index):
        self.stacked_widget.setCurrentIndex(index)

    # Handles logic for switching between the default/custom security questions
    def HandleSecurityQuestionType(self, securityQuestionType):
        if securityQuestionType == "Default":
            # Disable input for a custom question and set the default question text
            self.registrationSecurityQuestionInput.setDisabled(True)
            self.registrationSecurityQuestionInput.setText(
                "What is your first pet’s name?"
            )
        elif securityQuestionType == "Custom":
            # Enable input for a custom question and clear the default question
            self.registrationSecurityQuestionInput.setText(None)
            self.registrationSecurityQuestionInput.setDisabled(False)

    # Validates and processes the registration form data
    def HandleRegistrationFormValidation(self):
        self.messageLabelRegistration.setVisible(True)
        """
        This method validates the users input on the registration page, checks if the users email
        already exists in the Redis database, verifies that the passwords match, and ensures
        all the necessary input fields are filled out.
        """
        if self.registrationFirstNameInput.text() != "":
            if self.registrationEmailInput.text() != "":
                try:
                    if not redisConnection.exists(
                        f"user:{self.registrationEmailInput.text()}"
                    ):
                        if (
                            self.registrationPasswordInput.text() != ""
                            and self.registrationConfirmPasswordInput.text() != ""
                        ):
                            if (
                                self.registrationPasswordInput.text()
                                == self.registrationConfirmPasswordInput.text()
                            ):
                                if (
                                    self.registrationSecurityQuestionInput.text() != ""
                                    and self.registrationSecurityAnswerInput.text()
                                    != ""
                                ):
                                    print("Validation Passed. Creating Account.")
                                    """
                                    Calls the relevant functions to hash the password, create the account 
                                    in the Redis database, and navigate to the login page.
                                    """
                                    hashAndSalt = self.HashPassword(
                                        self.registrationPasswordInput.text()
                                    )
                                    self.CreateAccount(hashAndSalt)
                                    self.CleanupRegistrationForm()
                                    self.HandleNavigation(0)
                                    return
                                self.messageLabelRegistration.setText(
                                    "Please provide a security question and answer."
                                )
                                return
                            self.messageLabelRegistration.setText(
                                "Passwords don't match."
                            )
                            return
                        self.messageLabelRegistration.setText(
                            "Please enter a password for both fields."
                        )
                        return
                    self.messageLabelRegistration.setText("Account already exists.")
                    return
                except (RedisError, ConnectionError) as e:
                    print(f"An error occured during registration with redis: {e}")
                    return
            self.messageLabelRegistration.setText("Please enter a valid email address.")
            return
        self.messageLabelRegistration.setText("Please enter your first name.")
        print("Please enter your first name.")

    def HashPassword(self, password):
        """
        Hashes the password with a unique salt using the SHA-512 hashing algorithm
        """
        salt = uuid.uuid4().hex  # Creats a unique salt
        hashedPassword = hashlib.sha512(
            (password + salt).encode()
        ).hexdigest()  # Hashes the password with the unique salt
        return [hashedPassword, salt]  # Returns the hashed password and the salt

    def CreateAccount(self, hashAndSalt):
        try:
            """
            Stores the user's data in the Redis database using a Redis hash.
            """
            redisConnection.hset(
                f"user:{self.registrationEmailInput.text()}",
                mapping={
                    "password": hashAndSalt[0],
                    "salt": hashAndSalt[1],
                    "firstName": self.registrationFirstNameInput.text(),
                    "securityQuestion": self.registrationSecurityQuestionInput.text(),
                    "securityAnswer": self.registrationSecurityAnswerInput.text(),
                },
            )
        except (RedisError, ConnectionError) as e:
            print(f"Failed to create account with redis: {e}")

    def CleanupRegistrationForm(self):
        """
        Resets the registration form to its default state.
        """
        self.messageLabelRegistration.setVisible(False)
        self.messageLabelRegistration.setText(None)
        self.registrationEmailInput.setText(None)
        self.registrationPasswordInput.setText(None)
        self.registrationConfirmPasswordInput.setText(None)

    def HandleLoginFormValidation(self):
        try:
            self.messageLabelLogin.setVisible(True)
            """
            This method checks if the users email exists in the Redis database, verifies the password
            by comparing the hashed value with the stored hashed password, and logs the user in if successful.
            """
            if self.loginEmailInput.text() != "":
                if redisConnection.exists(f"user:{self.loginEmailInput.text()}"):
                    if self.loginPasswordInput.text() != "":
                        if self.ValidatePassword():
                            self.messageLabelLogin.setText("Successfully signed in!")
                            self.CleanupLoginForm()
                            self.HandleNavigation(0)
                            return
                        self.messageLabelLogin.setText("Incorrect credentials.")
                        return
                    self.messageLabelLogin.setText("Please enter a password.")
                    return
                self.messageLabelLogin.setText("Account does not exist.")
                return
            self.messageLabelLogin.setText("Please enter a valid email address.")
        except (RedisError, ConnectionError) as e:
            print(f"Failed to validate login with redis: {e}")

    def ValidatePassword(self):
        """
        Validates that the provided password matches the stored hash.
        """
        try:
            # Retrieves the stored hashed password and salt
            storedPassword = redisConnection.hmget(
                f"user:{self.loginEmailInput.text()}", ["password", "salt"]
            )
            # Hashes the provided password with the stored salt
            providedPassword = hashlib.sha512(
                (self.loginPasswordInput.text() + storedPassword[1]).encode()
            ).hexdigest()
            if providedPassword == storedPassword[0]:
                # If its a match return true i.e success
                return True
            # Else return false i.e failure
            return False
        except (RedisError, ConnectionError) as e:
            print(f"Failed to validate password with redis: {e}")
            return False

    def CleanupLoginForm(self):
        """
        Reset the login form to it's default state besides hiding the message alerts.
        """
        self.loginEmailInput.setText(None)
        self.loginPasswordInput.setText(None)

    def ValidateEmail(self):
        """
        Validates that the provided user email exists in the database.
        """
        try:
            self.messageLabelResetPassword.setVisible(True)
            if self.resetPasswordEmailInput.text() != "":
                if redisConnection.exists(
                    f"user:{self.resetPasswordEmailInput.text()}"
                ):
                    """
                    If the email exists, the security question against the users record is displayed
                    and the user is redirected to the next step in the password reset process.
                    """
                    self.securityQuestionLabel.setText(
                        redisConnection.hget(
                            f"user:{self.resetPasswordEmailInput.text()}",
                            "securityQuestion",
                        )
                    )
                    self.messageLabelResetPassword.setVisible(
                        False
                    )  # Hide the message label
                    self.HandleNavigation(3)
                    return
                self.messageLabelResetPassword.setText("Account does not exist.")
                return
            self.messageLabelResetPassword.setText("Please enter your email.")
        except (RedisError, ConnectionError) as e:
            print(f"Failed to validate email with redis: {e}")

    def ValidateSecurityQnA(self):
        """
        Validates that the provided security answer matches the stored answer
        """
        try:
            self.messageLabelSecurityQuestion.setVisible(True)
            if self.securityAnswerInput.text() != "":
                storedSecurityAnswer = redisConnection.hget(
                    f"user:{self.resetPasswordEmailInput.text()}", "securityAnswer"
                )
                if self.securityAnswerInput.text() == storedSecurityAnswer:
                    self.messageLabelSecurityQuestion.setVisible(
                        False
                    )  # Hide the message label
                    # Navigate to the update password page
                    self.HandleNavigation(4)
                    return
                self.messageLabelSecurityQuestion.setText("Incorrect answer.")
                return
            self.messageLabelSecurityQuestion.setText("Please enter an answer.")
        except (RedisError, ConnectionError) as e:
            print(f"Failed to validate security answer with redis: {e}")

    def ValidateNewPassword(self):
        """
        Validates that the 'new password' and the 'confirm new password' are entered and match.
        """
        self.messageLabelSetNewPassword.setVisible(True)
        if (
            self.newPasswordInput.text() != ""
            and self.confirmNewPasswordInput.text() != ""
        ):
            if self.newPasswordInput.text() == self.confirmNewPasswordInput.text():
                self.ResetPassword()  # Reset the password
                self.CleanupResetPasswordProcess()  # Reset the pages involved in the reset password process
                self.messageLabelSetNewPassword.setVisible(
                    False
                )  # Hide the message label
                self.HandleNavigation(0)  # Navigate to the login page
                print("Password Reset.")
                return
            self.messageLabelSetNewPassword.setText("Passwords do not match.")
            return
        self.messageLabelSetNewPassword.setText(
            "Please enter a password for both fields."
        )

    def ResetPassword(self):
        """
        Resets the password by hashing the new password and updating the database.
        """
        try:
            hashAndSalt = self.HashPassword(self.newPasswordInput.text())
            redisConnection.hset(
                f"user:{self.resetPasswordEmailInput.text()}",
                mapping={
                    "password": hashAndSalt[0],
                    "salt": hashAndSalt[1],
                },
            )
        except (RedisError, ConnectionError) as e:
            print(f"Failed to reset password with redis: {e}")

    def CleanupResetPasswordProcess(self):
        """
        Cleans up the reset password fields and resets the form to its default state.
        """
        self.resetPasswordEmailInput.setText(None)
        self.securityAnswerInput.setText(None)
        self.newPasswordInput.setText(None)
        self.confirmNewPasswordInput.setText(None)
        self.messageLabelResetPassword.setText(None)
        self.messageLabelSecurityQuestion.setText(None)
        self.messageLabelResetPassword.setText(None)


def LoadInitialDB():
    """
    This function is run to load Redis with test user data from a csv file.
    """
    try:
        # Transform the csv file into a dataframe for easier use
        csvName = "demo_users.csv"
        df = pd.read_csv(csvName)

        # Iterate over the dataframes rows and then prep and set the data into the Redis cache
        for index, row in df.iterrows():
            salt = uuid.uuid4().hex  # Generate a random salt
            hashedPassword = hashlib.sha512(
                (row["password"].strip() + salt).encode()
            ).hexdigest()  # Hash the password with the salt
            try:
                # Store the user in the db
                redisConnection.hset(
                    f"user:{row['username'].strip()}",
                    mapping={
                        "password": hashedPassword,
                        "salt": salt,
                        "firstName": row["firstname"].strip(),
                        "securityQuestion": "first dogs name",
                        "securityAnswer": row["first dogs name"].strip(),
                    },
                )
            except (RedisError, ConnectionError) as e:
                print(f"Failed to load user {row['username']} with redis: {e}")

        # Check to see if database size is the same as the csv size to see if all the users were set
        if redisConnection.dbsize() == df.shape[0]:
            print("Successfully loaded the initial database.")
        else:
            print("Something went wrong while loading the initial database.")
    except Exception as e:
        print(f"The initial database could not be loaded: {e}")


# Start <------------------------------ Tests ------------------------------>
# QApplication instance for the GUI tests
@pytest.fixture(scope="session")
def app_instance():
    app = QApplication([])
    return app


# Creates the main app window for testing
@pytest.fixture
def app_fixture(app_instance):
    app_window = AppWindow()
    return app_window


def test_registration(app_fixture):
    """
    User Registration Test
    This test simulates user registration by entering data into the form fields
    and verifying that the account is created in Redis.
    """
    try:
        app = app_fixture
        app.registrationFirstNameInput.setText("Test User")
        app.registrationEmailInput.setText("testuser@example.com")
        app.registrationPasswordInput.setText("password123")
        app.registrationConfirmPasswordInput.setText("password123")
        app.registrationSecurityAnswerInput.setText("Fluffy")
        app.createAccountButton.click()
        assert redisConnection.exists(
            "user:testuser@example.com"
        ), "User registration failed."
    except (RedisError, ConnectionError) as e:
        print(f"Failed to check if the test account exists with redis: {e}")


def test_login(app_fixture):
    """
    User Login Test
    This test simulates a user logging in by filling the login form and checks if
    the 'Successfully signed in!' message appears on the login page.
    """
    app = app_fixture
    app.loginEmailInput.setText("testuser@example.com")
    app.loginPasswordInput.setText("password123")
    app.loginButton.click()
    assert app.messageLabelLogin.text() == "Successfully signed in!"


def test_reset_password(app_fixture):
    """
    User Reset Password Test
    This test simulates a user resetting their password and checks if the user can
    log in successfully with the new credentials.
    """
    app = app_fixture

    app.resetPasswordEmailInput.setText("testuser@example.com")
    app.securityAnswerInput.setText("Fluffy")
    app.newPasswordInput.setText("not@password#okay")
    app.confirmNewPasswordInput.setText("not@password#okay")
    app.setNewPasswordButton.click()

    app.loginEmailInput.setText("testuser@example.com")
    app.loginPasswordInput.setText("not@password#okay")
    app.loginButton.click()
    assert app.messageLabelLogin.text() == "Successfully signed in!"


"""
Remove Test User
This test does'nt test any functionality it's just to ensure the test user is removed after each 
testing session.
"""


def test_remove_test_user():
    """
    Remove Test User
    This test ensures the test user is removed from the Redis database after testing.
    This is purely for testing clean-up and does not test any of the apps functionality.
    """
    try:
        redisConnection.delete("user:testuser@example.com")
        assert (
            redisConnection.exists("user:testuser@example.com") == 0
        ), "User was not removed."
    except (RedisError, ConnectionError) as e:
        print(f"Failed to delete test account with redis: {e}")


# End <------------------------------ Tests ------------------------------>

if __name__ == "__main__":
    app = QApplication(sys.argv)  # Initialise PyQt5
    appWindow = AppWindow()  # Create the app window using the AppWindow class
    appWindow.show()  # Display the window

    # Load initial database if the Redis database is empty (this may take a few seconds)
    try:
        if redisConnection.dbsize() == 0:
            LoadInitialDB()
    except (RedisError, ConnectionError) as e:
        print(f"Failed to check Redis DB size: {e}")

    sys.exit(app.exec_())  # Ensures the app exits cleanly
