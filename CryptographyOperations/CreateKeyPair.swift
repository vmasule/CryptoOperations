import Foundation
import Security

public class CreateKeyPair
{
    
    var publicKey : SecKey?
    var privateKey : SecKey?
    //var kSecAttrKeyTypeRSA: CFStringRef?
    var  osStatus:OSStatus?
    let parameters1: [String: AnyObject]
   //public let query: [String: AnyObject]
    
    init(){
        
        
        //Store in keychain with tag
        let publicKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): true,
            String(kSecAttrApplicationTag): "myPublicKey"
        ]
        
        let privateKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): true,
            String(kSecAttrApplicationTag): "myPrivateKey"
        ]
        
        parameters1 = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): 2048,
            kSecPublicKeyAttrs as String: publicKeyParameters,
            (kSecPrivateKeyAttrs as String) as String: privateKeyParameters
        ]
    
    }
    
    //Without storing in keychain
    //let parameters = [
      // String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        //String(kSecAttrKeySizeInBits): 2048
    //]
    

    
    func generateKeyPair()
    {
         osStatus = SecKeyGeneratePair(parameters1, &publicKey, &privateKey)
        
        if(osStatus != nil && osStatus == noErr)
        {
            print("Success------")
            print("public key is \(publicKey! as SecKeyRef)")
            print("Private key is \(privateKey! as SecKeyRef)")
            
        }else
        {
            print("Fail")
        }
    }
    
    func findKey(tag tag:String)-> SecKey?
    {
        let query: [String: AnyObject] = [
            String(kSecClass): kSecClassKey,
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tag,
            String(kSecReturnRef): true
        ]
        
        var keyPtr: AnyObject?
        let result = SecItemCopyMatching(query, &keyPtr)
        //let seckey:SceKey = nil
        
        switch result {
        case noErr:
            let key = keyPtr! as! SecKey
            print("Key is \(key)")
            return key
        case errSecItemNotFound:
            print("Eror")
            return nil
        default:
            print("Error occurred: \(result)")
            return nil
        }
        
        //return nil
    }
    
    func encript()
    {}

}