const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.send(`
    <h1>Hi, I'm Asiv, Yi people in China. 👋</h1>
    <p>Welcome to Sichuang and learn Yi people's culture!</p>
    <ul>
      <li>🔭 I’m now studying in Xidian university.</li>
      <li>🌱 I’m a pupil of Machine learning and Cybersecurity.</li>
      <li>🤔 I’m currently coding in Python and C++.</li>
      <li>❤️ I love travel, sleep and nature.</li>
      <li>💬 Occassionally, I like to lose myself in philosophical thought. Be free to ask me here.</li>
    </ul>
  `);
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
