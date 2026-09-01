const { io } = require("socket.io-client");

const socket = io("http://localhost:3000");

let latitude = 17.4483;
let longitude = 78.3915;

socket.on("connect", () => {
  console.log("Connected to server as Bus GPS Simulator!");

  setInterval(() => {
    latitude += 0.0004;
    longitude += 0.0004;

    const payload = {
      busId: "BUS-101",
      lat: latitude,
      lng: longitude,
      speed: 30,
      timestamp: new Date().toISOString()
    };

    console.log("Sending update:", payload);
    socket.emit("update-location", payload);
  }, 3000);
});

socket.on("disconnect", () => {
  console.log("Disconnected from server.");
});
