# Find a Campsite - User Authentication System

This project provides a user authentication system for the **'Find a Campsite'** application. It allows users to register, log in, and reset their passwords, using a Redis database for secure data storage. The system is implemented with **PyQt5** for the graphical user interface and uses **Redis** for managing user data.

## Features

- **User Registration**: Users can create an account by providing their first name, email, password, and security question/answer.
- **Login**: Users can log in with their email and password.
- **Password Reset**: Users can reset their password through a 3-step process: email input, security question validation, and password update.
- **Data Validation**: Ensures correct user input, checks for matching passwords, and verifies email uniqueness.
- **Secure Password Storage**: Passwords are hashed using the **SHA-512** algorithm and stored with a unique salt for security.
- **Automated Testing**: Comprehensive tests using `pytest` to ensure the correct functionality of registration, login, and password reset processes.
- **Redis Integration**: User data is securely stored in a Redis database, connected via a specified host, port, and password.

## Prerequisites

To run the application, ensure you have the following installed:

- **Python 3.8+**
- Redis server (local or remote)
- Required Python packages (install with the following command):

```bash
pip install redis PyQt5 pytest pandas
