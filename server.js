const app = require("./app");
const mongoose = require("mongoose");

mongoose
  .connect("mongodb://localhost:27017", {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
  })
  .then((result) => {
    console.log("Db connected");
  });

const port = process.env.PORT || 2501;
app.listen(port, (req, res) => {
  console.log(`listening on ${port}`);
});
