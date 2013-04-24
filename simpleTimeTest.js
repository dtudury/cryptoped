/**
 * Created with JetBrains WebStorm.
 * User: dtudury
 * Date: 4/24/13
 * Time: 12:16 PM
 * To change this template use File | Settings | File Templates.
 */
window.onload = function () {
    require(
        ['cryptoped'],
        function (cryptoped) {

            function writeTestOutput(pbkdf2Algo, algoName, password, salt, iterations, keyLength, correctOutput) {
                var output = pbkdf2Algo(password, salt, iterations, keyLength);
                if (output == correctOutput) {
                    document.write(algoName + " PASS: " + password + "," + salt + "," + iterations + "," + keyLength + "<br/>" + output + "<br/></br>");
                } else {
                    document.write(algoName + " FAIL!: " + password + "," + salt + "," + iterations + "," + keyLength + "<br/>" + output + " != " + correctOutput + "<br/></br>");
                }
            }

            function test(pbkdf2Algo, algoName, callback) {
                return function () {
                    var t0 = (new Date()).getTime();

                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 1, 32,
                        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 2, 32,
                        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 4096, 32,
                        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
                    //you probably don't want to run the next few tests through cryptoJs
//                    writeTestOutput(pbkdf2Algo, algoName, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
//                        "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
//                    writeTestOutput(pbkdf2Algo, algoName, "pass\0word", "sa\0lt", 4096, 16,
//                        "89b69d0516f829893c696226650a8687");
//                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 32768, 32,
//                        "2e179fd7692d201c2ff8aec6628af50b5d637a760668767ba8c56fb36828bad7");
                    //you probably don't want to run the next test at all... (takes around 5 minutes with cryptoped)
//                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 16777216, 32,
//                        "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46");

                    var t1 = (new Date()).getTime();

                    document.write(algoName + " total runtime: <br/>" + ((t1 - t0) / 1000) + "<br/><br/><br/><br/>");
                    console.log(algoName + " test complete " + ((t1 - t0) / 1000) + "\n\n");
                    callback();
                }

            }

            var cryptopedPbkdf2Algo = function (password, salt, iterations, keyLength) {
                var wordArray = cryptoped.pbkdf2(password, salt, iterations, keyLength);
                var output = "";
                for (var i = 0; i < wordArray.length; i++) {
                    string = (wordArray[i] >>> 0).toString(16);
                    while (string.length < 8) string = "0" + string;
                    output += string;
                }
                return output;
            }

            var cryptoJsPbkdf2Algo = function (password, salt, iterations, keyLength) {
                var keySize = 128 / 32;
                if (keyLength > 32) {
                    keySize = 512 / 32;
                } else if (keyLength > 16) {
                    keySize = 256 / 32;
                }
                var key256Bits = CryptoJS.PBKDF2(password, salt, { keySize: keySize, iterations: iterations, hasher: CryptoJS.algo.SHA256});
                return key256Bits.toString(CryptoJS.enc.Hex).slice(0, keyLength * 2);
            }


            setTimeout(test(cryptoJsPbkdf2Algo, "cryptoJs", function() {
                setTimeout(test(cryptopedPbkdf2Algo, "cryptoped", null), 0);
            }), 0);

        }
    );
}