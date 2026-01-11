// Frida script to read and log SSL/TLS keys from libssl
// This script hooks into the SSL_CTX_set_keylog_callback function to capture keys

let setKeylogCallbackName = "SSL_CTX_set_keylog_callback";
let sslReadName = "SSL_read";
let sslGetContextName = "SSL_get_SSL_CTX";


// First, just verify that libssl is loaded
function returnSSLModule() {
  let modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {
      if (modules[i].name.indexOf("libssl.so") !== -1) {
          console.log("libssl is loaded: " + modules[i].name);
          return modules[i];
      }
  }
}

// SSL_CTX_set_keylog_callback uses a callback that passes the SSL pointer and a line of text
// containing the key information. We will define this callback to log the keys.
function keylogCallbackFunc(ssl, line) {
  var keyLine = line.readUtf8String();
  console.log(keyLine);
  send({type: "keylog", data: keyLine});
}

// Function to find the SSL_CTX_set_keylog_callback function address
function returnFunctionFromName(sslModule, sslFunctionName) {
  let SSL_CTX_set_keylog_callbackAddr = sslModule.findExportByName(sslFunctionName);
  if (SSL_CTX_set_keylog_callbackAddr !== null) {
      console.log("Found " + sslFunctionName + " at: " + SSL_CTX_set_keylog_callbackAddr);
      return SSL_CTX_set_keylog_callbackAddr;
  }
}

// Function to hook SSL_CTX_set_keylog_callback and set our custom callback
function createCallBack() {
  // Define the callback function to log the keys
  var keylogCallback = new NativeCallback(keylogCallbackFunc, 'void', ['pointer', 'pointer']);
  return keylogCallback;
}

// Function to find the file descriptor of the socket associated with an SSL connection
function findConnectionFD(sslModule) {
  var SSL_get_fdAddr = sslModule.findExportByName("SSL_get_fd");
  if (SSL_get_fdAddr !== null) {
      console.log("Found SSL_get_fd at: " + SSL_get_fdAddr);
      return SSL_get_fdAddr;
  }
}

function main(){
  // Get the module for libssl
  let sslPtr = NULL;
  let sslModule = returnSSLModule();
  
  if (sslModule === undefined) {
      console.log("libssl module not found, exiting script.");
      return;
  }

  // Get the function set_keylog_callback address
  let setKeylogCallbackFunc = returnFunctionFromName(sslModule, setKeylogCallbackName);

  // Get the SSL_read function address
  let readFunc = returnFunctionFromName(sslModule, sslReadName);
  // Create the native callback function
  let nativeCallback = createCallBack();
  // Get the SSL_get_SSL_CTX function address
  let sslGetContextNameFunc = returnFunctionFromName(sslModule, sslGetContextName);
  
  let sslCtxPtr = NULL;

  // Create a NativeFunction for SSL_get_SSL_CTX
  let sslGetContextFuncNative = new NativeFunction(sslGetContextNameFunc, 'pointer', ['pointer']);

 

  // Intercept a read call to retrieve the SSL_CTX pointer
  let interceptor = Interceptor.attach(readFunc, {
      onEnter: function (args) {
          sslPtr = args[0];
          console.log("SSL pointer from SSL_read: " + sslPtr);
          sslCtxPtr = sslGetContextFuncNative(sslPtr);
          console.log("SSL_CTX pointer from SSL_get_SSL_CTX: " + sslCtxPtr);
          let setKeylogCallbackNativeFunc = new NativeFunction(setKeylogCallbackFunc, 'void', ['pointer', 'pointer']);
          setKeylogCallbackNativeFunc(sslCtxPtr, nativeCallback);
          interceptor.detach(); // Detach after first call to avoid overhead
          }
      });



  
  //let SSL_get_fdAddr = findConnectionFD(sslModule);

}

main();
