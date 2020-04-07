import * as fs from "fs";
import * as path from "path";
import * as AWS from "aws-sdk";
import * as openpgp from "openpgp";

const args = process.argv.slice(2);
const env = args[0];
const s3Bucket = args[1];
const awsProfile = args[2];
const runningOption = args[3];
const secretsId: string = "/" + process.env.ENVIRONMENT + "/privatekeypassphrase"

process.env.ENVIRONMENT = args[0];
process.env.S3_BUCKET = args[1];

var credentials = new AWS.SharedIniFileCredentials({ profile: awsProfile });
AWS.config.region = "us-east-1";
AWS.config.credentials = credentials;

var secretsManager = new AWS.SecretsManager();
var s3 = new AWS.S3();

export class GPGEncryptionSecret {
  privateKeyPassphrase: string;
  submitHost: string;
  submitUserName: string;
  submitPassword: string;
  retrieveUserName: string;
  retrievePassword: string;
}

export class EncryptionSetup {
  secrets: GPGEncryptionSecret;
  publicKeyArmored: string;
  privateKey: Buffer;
  privateKeyPassphrase: string;
}

var walk = function(dir, done) {
  var results = [];
  fs.readdir(dir, function(err, list) {
    if (err) return done(err);
    var i = 0;
    (function next() {
      var file = list[i++];
      if (!file) return done(null, results);
      file = path.resolve(dir, file);
      fs.stat(file, function(err, stat) {
        if (stat && stat.isDirectory()) {
          walk(file, function(err, res) {
            results = results.concat(res);
            next();
          });
        } else {
          results.push(file);
          next();
        }
      });
    })();
  });
};

async function walkPromise(directory: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    walk(directory, function(err, results) {
      if (err) {
        reject(err);
      }
      resolve(results);
    });
  });
}

async function loadStreamingFile(bucketName, s3KeyName): Promise<any | any[]> {
  const streamFunction = function(resolve, reject) {
    const results = [];
    s3.getObject({
      Bucket: bucketName,
      Key: s3KeyName
    })
      .createReadStream()
      .on("data", data => {
        results.push(data);
      })
      .on("error", err => {
        reject(err);
      })
      .on("end", () => {
        resolve(results);
      });
  };
  return new Promise(
    streamFunction.bind({
      s3: s3
    })
  );
}

async function retrieveSecrets(secretsId: string): Promise<
  AWS.SecretsManager.GetSecretValueResponse
> {
  return secretsManager.getSecretValue({ SecretId: secretsId }).promise();
  //   if ("SecretString" in secretsResponse) {
  //     console.log(`secret found!`);
  //     return JSON.parse(secretsResponse.SecretString) as TObject;
  //   } else {
  //     console.error(`Could not find secret ${secretsId}`);
  //     throw new Error("Could not find secret");
  //   }
}

async function getEncryptionSettings(secretsId: string): Promise<EncryptionSetup> {
  const publicKeyS3Location = "keys/DonKros_key.asc";
  const privateKeyS3Location = "keys/DonKros_secret.gpg";

  console.log(`Retrieving secrets from secrets manager!`);
  const secretsPromise = retrieveSecrets(secretsId);

  const publicKeyArmoredPromise = loadStreamingFile(
    process.env.S3_BUCKET,
    publicKeyS3Location
  );

  const privateKeyPromise = loadStreamingFile(
    process.env.S3_BUCKET,
    privateKeyS3Location
  );

  let [secretsResponse, publicKeyArmored, privateKey] = await Promise.all([
    secretsPromise,
    publicKeyArmoredPromise,
    privateKeyPromise
  ]);
  const secrets = JSON.parse(secretsResponse.SecretString) as GPGEncryptionSecret;
  const privateKeyPassphrase = secrets.privateKeyPassphrase;

  if (Array.isArray(privateKey)) {
    privateKey = privateKey[0];
  }

  return {
    secrets,
    publicKeyArmored,
    privateKey,
    privateKeyPassphrase
  };
}


async function encryptFile(
  publicKeyArmored: string,
  privateKey: Buffer,
  passphrase: string,
  cipherText: string
) {
  openpgp.initWorker({ path: "openpgp.worker.js" });

  const privateKeyDecrypted = (await openpgp.key.read(privateKey)).keys[0];
  await privateKeyDecrypted.decrypt(passphrase);

  // encrypted.data ~ ReadableStream containing '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
  // encrypted.message.packets.write() ~ binary representation of openpgp objects
  const encrypted = await openpgp.encrypt({
    message: openpgp.message.fromText(cipherText), // input as Message object
    publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for encryption
    privateKeys: [privateKeyDecrypted], // for signing (optional),
    armor: false
  });
  return encrypted.message.packets.write();
}

async function encryptDirectory(
    encryptionSettings: EncryptionSetup,
    encryptDir: string = "./data/encrypted/"
  ) {
  let encryptedFilesPromise = [];
  const decryptedFiles = await walkPromise(
    path.join(__dirname, encryptDir)
  );
  
  // filter out the encrypted files
  for (var file of decryptedFiles.filter(x => x.endsWith('_out.txt'))) {
    console.log(`Encrypting file ${file}`);
    const encryptedFileName = file.replace("_out.txt", "_out.txt.gpg");
    const fileBuffer = fs.readFileSync(file);
    const encryptedFile = await encryptFile(
      encryptionSettings.publicKeyArmored.toString(),
      encryptionSettings.privateKey,
      encryptionSettings.privateKeyPassphrase,
      fileBuffer.toString()
    );
    fs.writeFileSync(encryptedFileName, encryptedFile);
  }
  }
  
async function decryptFile(
  publicKeyArmored: string,
  privateKey: Buffer,
  passphrase: string,
  cipherText: Buffer
) {
  openpgp.initWorker({ path: "openpgp.worker.js" }); 
  
  const privateKeyDecrypted = (await openpgp.key.read(privateKey)).keys[0];
  await privateKeyDecrypted.decrypt(passphrase);

  const decrypted = await openpgp.decrypt({
    message: await openpgp.message.read(cipherText), // parse armored message
    publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for verification (optional)
    privateKeys: [privateKeyDecrypted] // for decryption
  });
  // @ts-ignore
  return await openpgp.stream.readToEnd(decrypted.data);
}

async function decryptDirectory(
  encryptionSettings: EncryptionSetup,
  decryptDir: string = "./data/encrypted/"
) {
  let decryptedFilesPromise = [];
  const encryptedFiles = await walkPromise(
    path.join(__dirname, decryptDir)
  );

  // filter to only the encrypted files, the unencrypted files might also be present
  for (var file of encryptedFiles.filter(x => x.endsWith('_out.txt.gpg'))) {
    console.log(`Decrypting file ${file}`);
    const decryptedFileName = file.replace("_out.txt.gpg", "_out.txt");
    const fileBuffer = fs.readFileSync(file);
    const decryptedFile = await decryptFile(
      encryptionSettings.publicKeyArmored.toString(),
      encryptionSettings.privateKey,
      encryptionSettings.privateKeyPassphrase,
      fileBuffer
    );
    console.log(`Saving file ${decryptedFileName}`);
    fs.writeFileSync(decryptedFileName, decryptedFile);
  }
}

async function processHandler(encryptionOption: string, secretsId: string) {
  const encryptionSettings = await getEncryptionSettings(secretsId);
  switch (encryptionOption) {
    case "decryption": {
      return await decryptDirectory(encryptionSettings);
    }
    case "encryption": {
      return await encryptDirectory(encryptionSettings);
    }
    default: {
      console.log(
        `Not sure what option you were trynig to do ${encryptionOption} is not valid`
      );
      process.exit(-1);
    }
  }
  // return await decryption(publicKey, privateKey, cipherText);
  return "success!";
}

processHandler(args[3], secretsId)
  .then(data => {
    console.log("success!");
  })
  .catch(err => {
    console.log("error!");
    console.error(err);
  });
