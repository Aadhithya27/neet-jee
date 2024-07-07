<?php
$name = $_POST['name'];
$visitor_email = $_POST['email'];
$age = $_POST['age'];
$message = $_POST['message'];

$email_from = 'gagzo@hosp.com';

$email_subject = 'New From Submission';

$email_body = "User Name: $name.\n".
                "User Email: $visitor_email.\n". 
                "Subject: $subject.\n".
                "User Message: $message.\n".;

$to = 'gokulvenkat4425@gmail.com';

$headers = "From: $email_from \r\n";

$headers .= "Reply-To: $visitor_email \r\n";

mail($to,$email_subject,$email_body,$headers);

header("Location: contact.html");

//booking system

$servername = "localhost";
$username = "root";
$password = "";
$dbanme = "bookings";
$conn = new mysqli($servername, $username, $password, $dbanme);

if($conn->connect_error){
    die("Connection Failed:" .$conn->connect_error);
}

//handle for submission
if($_SERVER["REQUEST_METHOD"] == "POST"){
    $name = $_POST["name"];
    $email = $_POST["email"];
    $phonenumber = $_POST["phonenumber"];
    $dob_date =$_POST["dob_date"];

    //database
    $sql = "INSERT INTO 'booking'('name','email', 'phonenumber', 'dob_date') VALUES('$name','$email','$phonenumber','$dob_date')";

    if ($conn->query($sql) == TRUE){
        echo "Booking Successfully";
    }else{
        echo "Error: " .$sql . "<br>" .$conn->error;
    }
}
$conn->close();
?>