# BruteWeb - Web Application Brute-Force Tool

[![Version](https://img.shields.io/badge/Version-0.99-blue.svg)](https://github.com/Superjulien/Bruteweb) [![License](https://img.shields.io/badge/License-GNU_GPLv3-blue.svg)](https://choosealicense.com/licenses/gpl-3.0/) [![Python](https://img.shields.io/badge/Python_3-14354C?&logo=python&logoColor=white.svg)](https://www.python.org/)

BruteWeb is a Python script designed for security testing of web applications, specifically for conducting Brute-Force attacks on web applications. This tool attempts to gain unauthorized access to web applications by trying different combinations of usernames and passwords.

**Note: The use of this tool is strictly reserved for legal and ethical purposes. Make sure to have the authorization of the owner of the targeted web application before using BruteWeb. Unauthorized use of this tool may be illegal and is strongly discouraged.**

## Features

- **Brute-Force Attack**: BruteWeb performs a Brute-Force attack on the target web application by trying multiple combinations of usernames and passwords to gain unauthorized access. It uses a provided error message to identify unsuccessful login attempts.

- **Command-Line and Graphical User Interface (GUI) Modes**: BruteWeb supports both command-line and graphical user interface (GUI) modes. The command-line mode allows advanced users to run the script, while the GUI mode offers a user-friendly interface to interactively enter the required parameters along with various options and arguments.

- **Customizable User Agent**: Users can specify a custom User-Agent string to use for HTTP requests. This allows users to simulate different web browsers or devices to test the behavior of the web application under different User-Agent headers.

- **Username and Password Form Fields**: BruteWeb allows users to specify the names of the form fields for the username and password in the web application's login form. This flexibility accommodates different designs of web applications that may use different form field names for login credentials.

- **Verbosity Levels**: Users can control the level of verbosity during the brute-force attack. The verbosity levels are as follows:
  - `none`: Minimal output (only success or failure).
  - `-v`: Standard output (also displays attempted combinations and task IDs).
  - `-vv`: User:Pass output (displays attempted username:password combinations).
  - `-vvv`: User:Pass + Response output (displays both combinations and web application responses).

- **Parallel Execution with Multi-Threading**: To expedite the brute-force attack, BruteWeb supports multi-threading for parallel execution of multiple tasks. Users can specify the number of parallel tasks to run concurrently, enhancing the speed of the brute-force process.

- **Sleep Timer**: Users can add a time delay (in seconds) between login attempts using the `-t` option. This feature is useful for avoiding detection and rate limiting by the target web application during the brute-force attack.

- **Detailed Output**: BruteWeb provides detailed output during the brute-force attack, including the attempted combinations and responses from the target web application. This information aids in analyzing the results of the attack and identifying successful login credentials.

- **All Combinations**:  Users have the option to try all possible combinations of usernames and passwords, regardless of whether a valid combination is found, providing a thorough testing approach.

## Getting Started

To use BruteWeb for security testing on your web applications, follow these steps:

1. Clone the repository to your local machine.
2. Run BruteWeb from the command line with the desired options, or launch the GUI mode to interactively configure the attack.

**Note: Remember to use BruteWeb responsibly and only on web applications that you have explicit permission to test. Unauthorized access to web applications is illegal and unethical.**

### Requirements:

- Python 3.x
- `mechanize` library (can be installed using `pip`: `pip install mechanize`)

### Installation:

To use BruteWeb, you need to have Python 3.x installed on your system. Additionally, you must install the `mechanize` library. You can install it using `pip` by running the following command:

```
pip3 install mechanize
```

### Downloading Bruteweb:

To download the Bruteweb script and start using it for web security testing, follow these simple steps:

1. **Clone the Repository:**
   - Bruteweb is hosted on a Git repository for easy access. You can clone the repository to your local machine using the following command:

   ```
   git clone https://github.com/Superjulien/Bruteweb.git
   ```

   This command will create a local copy of the Bruteweb script and its associated files in a directory called `Bruteweb` on your machine.

2. **Navigate to the Directory:**
   - Once the cloning process is complete, navigate to the `Bruteweb` directory:

   ```
   cd Bruteweb
   ```

## Usage

### Command-Line Mode:

To run BruteWeb in command-line mode, use the following syntax:

```
python3 bruteweb.py URL USERNAME_FILE PASSWORD_FILE ERROR_MESSAGE [-t TIME] [-c HEADER] [-u USERNAME_FIELD] [-p PASSWORD_FIELD] [-v {-v,-vv,-vvv}] [-n TASKS] [-a]
```

**Arguments:**
- `URL`: The target URL of the web application.
- `USERNAME_FILE`: Path to the file containing a list of usernames to try.
- `PASSWORD_FILE`: Path to the file containing a list of passwords to try.
- `ERROR_MESSAGE`: The error message displayed by the web application upon unsuccessful login attempts.

**Optional Arguments:**
- `-t TIME`: Time (in seconds) to sleep between login attempts to avoid detection (default: 0).
- `-c HEADER`: Custom user-agent string to use for HTTP requests (default: Mozilla/5.0...).
- `-u USERNAME_FIELD`: Form field name for the username (default: 'username').
- `-p PASSWORD_FIELD`: Form field name for the password (default: 'password').
- `-v {-v,-vv,-vvv}`: Verbosity level (none: minimal output, -v: standard output, -vv: user:pass output, -vvv: user:pass + response output) (default: None).
- `-n TASKS`: Number of parallel tasks to run (default: 1).
- `-a`: This option instructs the tool to try all possible combinations of usernames and passwords, even if a valid combination is found. (default: None)

### GUI Mode:

The GUI allows users to input the required parameters using text fields and checkboxes and initiate the brute-force attack with a click of the "Run" button.

**Note:** The GUI requires the `tkinter` library, which is typically included with standard Python installations.

1. Launch the Brute Web GUI by running the script with the `-g` or `--gui` option from the command line.
2. The GUI window will open, displaying various input fields and options for customization.
3. Fill in the required information in the input fields as described above.
4. If you have provided all the necessary details, click the "Run" button to start the brute-force attack.
5. The brute-force attack will begin, and the output will be displayed in the "Console" section of the GUI.
6. The output will show the progress of the attack, including attempted username-password combinations and server responses.
7. If valid login credentials are found, they will be displayed in the output.

#### Customizable User Experience:

The Brute Web GUI is designed to be customizable to suit different testing scenarios and user preferences. Here are some ways you can personalize the experience:

1. **Customize User-Agent**: By enabling the "Custom User-Agent" option, you can provide your custom User-Agent header. This allows you to mimic different browsers or devices during the attack.

2. **Adjust Verbosity**: The "Verbosity" option allows you to choose the level of detail in the output. Increase the verbosity for more detailed logs, or reduce it for a more concise output.

3. **Time Delay**: You can introduce a time delay between login attempts by enabling the "Time (Sleep m/s)" option and specifying the delay in milliseconds. This can be useful to avoid triggering rate-limiting mechanisms on the target website.

4. **Form Field Names**: If the login form on the target website requires specific field names for the username and password, you can provide them by enabling the "Form for Username" and "Form for Password" options.

5. **Number of Parallel Tasks**: The "Number of Parallel Tasks" option allows you to control the level of parallelism in the brute-force attack. Increasing the number of tasks can speed up the attack but may also increase the load on the target server.

6. **Try all combinations**: "Try all combinations" option is particularly useful in situations where you want to conduct comprehensive security tests by testing every possible combination of usernames and passwords. However, it is important to note that using this option with large lists of usernames and passwords can be extremely time-consuming and resource-intensive.

## Finding the Error Message

To use the BruteWeb script, you need to identify the specific error message displayed by the web application during an unsuccessful login attempt. This is a crucial element for the script to recognize successful and unsuccessful login attempts.

Here's how to find the required error message for the `ERROR_MESSAGE` argument:

1. **Identify an Unsuccessful Login Attempt**:
   - Open the target web application.
   - Attempt to log in using an incorrect username and password.
   - Pay close attention to the message displayed on the page after the unsuccessful attempt. This message typically indicates that the provided credentials are incorrect.

2. **Copy the Error Message**:
   - Select the error message with your mouse and copy it to your system's clipboard.

3. **Paste the Message into the `ERROR_MESSAGE` Argument**:
   - When running the BruteWeb script, use the copied error message as the value for the `ERROR_MESSAGE` argument.
   - Make sure to keep the double or single quotes around the error message, as they indicate to the script the exact string to look for in the HTTP response.

For example, if the error message after an unsuccessful login attempt to the target web application is: "Incorrect username or password. Please try again."

When executing the script in command-line mode, you will use the `ERROR_MESSAGE` argument as follows:

```
python3 bruteweb.py http://example.com/login usernames.txt passwords.txt "Incorrect username or password. Please try again."
```

If the error message you provided matches exactly with the one returned by the web application after an unsuccessful attempt, the BruteWeb script will recognize unsuccessful login attempts and stop the brute-force process once a successful combination of username and password is found.

In summary, the `ERROR_MESSAGE` argument is essential to allow the BruteWeb script to determine whether a login attempt was successful or not. You need to identify the appropriate error message in the target web application and provide it to the script for it to conduct the brute-force attack successfully.

## Finding the Username Form Field Name or Password Form Field Name

### To find the username form field name, follow these steps:

1. **Open the Login Page**:
   - Access the login page of the target web application in your web browser.

2. **Inspect Element**:
   - Right-click on the username input field on the login page.
   - From the context menu that appears, select "Inspect" or "Inspect Element" (depending on your browser). This will open the browser's developer tools.

3. **Locate the Username Form Field**:
   - In the developer tools, the HTML code of the web page will be displayed, and the corresponding element for the username input field will be highlighted.

4. **Identify the Input Element**:
   - Look for an HTML input element that represents the username input field. It will typically have a type attribute set to "text" or "email".

5. **Find the Form Field Name**:
   - Locate the "name" attribute of the input element. The "name" attribute contains the form field name associated with the username input.

6. **Note the Form Field Name**:
   - The value of the "name" attribute is the username form field name that you need to use in the BruteWeb script.

For example, if the HTML input element for the username field looks like this:

```html
<input type="text" name="username" id="username-input" />
```

The form field name for the username is "username", and you will use it as the value for the `-u` or `--usern` argument when running the BruteWeb script.

When executing the script in command-line mode, you will use the username form field name as follows:

```
python3 bruteweb.py http://example.com/login usernames.txt passwords.txt -u username
```

### To find the password form field name on a login page, follow these steps:

1. **Open the Login Page**:
   - Access the login page of the target web application in your web browser.

2. **Inspect Element**:
   - Right-click on the password input field on the login page.
   - From the context menu that appears, select "Inspect" or "Inspect Element" (depending on your browser). This will open the browser's developer tools.

3. **Locate the Password Form Field**:
   - In the developer tools, the HTML code of the web page will be displayed, and the corresponding element for the password input field will be highlighted.

4. **Identify the Input Element**:
   - Look for an HTML input element that represents the password input field. It will typically have a type attribute set to "password".

5. **Find the Form Field Name**:
   - Locate the "name" attribute of the input element. The "name" attribute contains the form field name associated with the password input.

6. **Note the Form Field Name**:
   - The value of the "name" attribute is the password form field name that you need to use in the BruteWeb script.

For example, if the HTML input element for the password field looks like this:

```html
<input type="password" name="password" id="password-input" />
```

The form field name for the password is "password", and you will use it as the value for the `-p` or `--passn` argument when running the BruteWeb script.

When executing the script in command-line mode, you will use the password form field name as follows:

```
python3 bruteweb.py http://example.com/login usernames.txt passwords.txt -p password
```

## How Bruteweb Works

Bruteweb is a tool designed for conducting brute-force attacks to assess the security of web applications. Below is a detailed explanation of how the script operates:

1. **Initialization:**
   - Bruteweb starts by initializing the required variables, settings, and parameters.
   - It parses the command-line arguments provided by the user, including the target URL, username and password files, custom error message, time delay, User-Agent, verbosity level, form field names, number of tasks, and the "try all combinations" flag.

2. **Configuration and Input Validation:**
   - The script validates the user-provided inputs, ensuring that mandatory parameters are provided, and values are within acceptable ranges.
   - It checks the validity of the URL format and ensures that the provided files for usernames and passwords exist.

3. **Parallel Task Execution:**
   - If the user specifies a number of tasks greater than 1 (using the `-n` option), Bruteweb executes the attack using multiple parallel tasks to increase efficiency.
   - Each task is responsible for testing a portion of the username and password combinations.

4. **Username and Password Lists:**
   - Bruteweb reads the lists of usernames and passwords from the provided files.
   - It generates combinations of usernames and passwords to be used for authentication attempts.

5. **HTTP Request Preparation:**
   - For each combination of credentials, the script prepares an HTTP request to the target URL.
   - It configures the User-Agent header to mimic a specific browser or device if a custom User-Agent is provided.

6. **Authentication Attempt:**
   - The script submits the HTTP request with the username and password combination to the target URL.
   - It captures the server's response, which may contain an error message or login success confirmation.

7. **Response Analysis:**
   - Bruteweb analyzes the server's response to determine whether the authentication attempt was successful or not.
   - It checks if the response contains the provided error message, indicating a failed login attempt.
   - If a valid combination is found, the script logs the credentials and the server's response.

8. **Logging and Output:**
   - The tool provides detailed logs based on the chosen verbosity level.
   - Users can select the desired verbosity level to control the amount of information displayed in the logs, from minimal to highly detailed.
   - The logs include the progress of the attack, the combinations being tested, and the server's responses.

9. **Completion and Results:**
   - Bruteweb continues the attack until all specified combinations have been tested or until the user interrupts the process.
   - If a successful login combination is found, the script logs and displays the credentials.
   - Users can determine the success of the attack based on the logged results.

10. **GUI Mode (Optional):**
    - Bruteweb offers a Graphical User Interface (GUI) mode for users who prefer a user-friendly interface.
    - In GUI mode, users can configure the attack settings through a graphical interface, making it accessible to those without extensive technical knowledge.

Overall, Bruteweb provides a flexible and configurable approach to web security testing through brute-force attacks, allowing security professionals and ethical hackers to assess the strength of web applications and identify potential vulnerabilities. Users can customize the attack parameters and analyze the results to enhance web security.

### Verbose Levels:

Bruteweb provides different verbosity levels that control the amount of detail in the log output. Users can choose the appropriate verbosity level based on their need for information and analysis. Here's what each verbosity level entails:

1. **Verbose Level 0 (`None` or Default):**
   - **Description:** This is the lowest verbosity level and provides minimal output.
   - **Use Case:** Level 0 is suitable when you want concise information and only need to know if the attack succeeded or failed without diving into details.

2. **Verbose Level 1 (`-v`):**
   - **Description:** Description: Verbosity Level 1 is the highest verbosity level. It includes a summary of the selected options, such as the URL, form fields used, and custom User-Agent. Additionally, when used in combination with the -a option, it displays the total number of possible authentication attempts to be made, as well as the number of attempts performed.
   - **Use Case:**  This level is useful when you want an overview of the attack configuration and progress. It helps you understand the chosen settings and keeps track of the total and completed authentication attempts, especially when the -a option is used to try all possible combinations.

3. **Verbose Level 2 (`-vv`):**
   - **Description:** Level 2 provides intermediate verbosity, including the login and password combinations being tested.
   - **Use Case:** This level is suitable when you want to monitor the progress of the attack closely and see the specific username and password combinations being used.

4. **Verbose Level 3 (`-vvv`):**
   - **Description:** Level 3 provides even more detailed output, offering comprehensive information.
   - **Use Case:** It's perfect for conducting thorough analysis and debugging, as it offers a comprehensive view of the server's response to each authentication attempt, including the login and password combinations being tested.

## Examples

#### Command-Line Mode:
```
python3 bruteweb.py http://example.com/login usernames.txt passwords.txt "Invalid username or password" -t 2 -vv -a -n 10
```

#### GUI Mode:
```
python3 bruteweb.py -g
```
## Upcoming Features

1. Enhanced Graphical Interface : 
    A more user-friendly and aesthetically pleasing user interface to provide a better experience for users.
    Addition of notifications and pop-up windows to inform the user about the brute-force process status and results.

2. More Robust Error Handling : 
    Improved error and exception handling for a smoother user experience.
    Implementation of more comprehensive validation of user inputs to ensure the provided parameters are valid.

3. Support for Secure Connections : 
    Addition of features to support HTTPS connections with secure websites.

4. Automated Testing :
    Implementation of automated tests to verify the proper functioning of the program in different scenarios and configurations.

5. Improved Synchronization : 
    Enhancing thread synchronization to avoid any issues with concurrent access to shared resources.

6. Performance Enhancement : 
    Program optimization for better resource management and performance.

7. Expanded Command-Line Interface : 
    Addition of new options and features to the command-line interface.

8. Proxy Support : 
    Addition of features to use proxies for HTTP requests to ensure anonymity during security testing.

9. Result Export : 
    Addition of the ability to export brute-force results in different formats, such as CSV or JSON.

## Sponsoring

This software is provided to you free of charge, with the hope that if you find it valuable, you'll consider making a donation to a charitable organization of your choice :

- SPA (Society for the Protection of Animals): The SPA is one of the oldest and most recognized organizations in France for the protection of domestic animals. It provides shelters, veterinary care, and works towards responsible adoption.

  [![SPA](https://img.shields.io/badge/Sponsoring-SPA-red.svg)](https://www.la-spa.fr/)

- French Popular Aid: This organization aims to fight against poverty and exclusion by providing food aid, clothing, and organizing recreational activities for disadvantaged individuals.

  [![SPF](https://img.shields.io/badge/Sponsoring-Secours%20Populaire%20Français-red.svg)](https://www.secourspopulaire.fr)

- Doctors Without Borders (MSF): MSF provides emergency medical assistance to populations in danger around the world, particularly in conflict zones and humanitarian crises.

  [![MSF](https://img.shields.io/badge/Sponsoring-Médecins%20Sans%20Frontières-red.svg)](https://www.msf.fr)

- Restaurants of the Heart : Restaurants of the Heart provides meals, emergency accommodation, and social services to the underprivileged.

  [![RDC](https://img.shields.io/badge/Sponsoring-Restaurants%20du%20Cœur-red.svg)](https://www.restosducoeur.org)

- French Red Cross: The Red Cross offers humanitarian aid, emergency relief, first aid training, as well as social and medical activities for vulnerable individuals.

   [![CRF](https://img.shields.io/badge/Sponsoring-Croix%20Rouge%20Française-red.svg)](https://www.croix-rouge.fr)

Every small gesture matters and contributes to making a real difference.

## License

BruteWeb is open-source software released under the [GNU GPLv3 License](https://choosealicense.com/licenses/gpl-3.0/). This license allows users of this software to use it, modify it, distribute it, and share it freely while preserving transparency and collaboration.

## Disclaimer

The use of BruteWeb for unauthorized purposes is illegal and unethical. Use this tool responsibly and only on web applications for which you have permission to perform security testing.

The developers and contributors of BruteWeb are not responsible for any misuse or damage caused by the use of this tool.

## Support
For support email : 

[![Gmail: superjulien](https://img.shields.io/badge/Gmail-Contact%20Me-purple.svg)](mailto:contact.superjulien@gmail.com) [![Tutanota: superjulien](https://img.shields.io/badge/Tutanota-Contact%20Me-green.svg)](mailto:contacts.superjulien@tutanota.com)
