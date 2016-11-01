(client, callback) => {
  // let storage = gs.connection.localStorageProvider,
  //     obj = { objectId: 'my id', name: 'Vladka' };
  // console.log(Object.keys(application.security));
  // console.log(Object.keys(api.globalstorage.localStorageProvider));
  // console.log(Object.keys(gs.connection));
  // storage.find({}, (err, data) => console.log(err, data));
  // gs.localStorageProvider.find({}, (err, data) => {
  //   console.log(err, data);
  // });
  application.security.signOut('43dc3c1e-bb99-4a3b-a8c4-41a73480e364', (err, sid) => {
    console.log(err, sid);
  });
  callback({ a: 4 });
}
