//
//  IdentityFileReader.swift
//  CryptographyOperations
//
//  Created by Bhaidas Masule on 29/09/2015.
//  Copyright © 2015 NGO. All rights reserved.
//

import Foundation
import Security

class IdentityFileReader {
    
    //MARK: Properties
    
    
    func readePKCS12File()-> OSStatus {
    
        var osStatus = errSecAllocate
        var pkcs12Data: CFDataRef?
        
        let path = NSBundle.mainBundle().pathForResource("AuthServer", ofType: ".p12")
        
        do {
            let data = try NSData(contentsOfFile: path!, options: NSDataReadingOptions.DataReadingMappedIfSafe)
            pkcs12Data = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
        } catch {
            
        }
        
        var keyRef: CFArray?
        
        let optionDictionary: NSMutableDictionary = NSMutableDictionary()
        optionDictionary.setValue("password", forKey: kSecImportExportPassphrase as String)
        
        osStatus = SecPKCS12Import(pkcs12Data!, optionDictionary, &keyRef)
        
        if osStatus != 0 {
        
            print("Error occurred while importing file")
            
        }else {
        
            print("PKCS12 file imported sucessfully")
        }
        
        //Copy array 
        let cfArrayData: CFString = CFCopyDescription(keyRef)
        print(cfArrayData)
        print("Count is \(CFArrayGetCount(keyRef))")
        
        //MARK: Get Identity & Trust
        
        let identityDictionaryPointer = CFArrayGetValueAtIndex(keyRef , 0)
        
        let identityDictionaryRef: CFDictionaryRef = unsafeBitCast(identityDictionaryPointer, CFDictionaryRef.self)
        
        let identityPointer = CFDictionaryGetValue(identityDictionaryRef, unsafeAddressOf(kSecImportItemIdentity))
        
        let trustPointer = CFDictionaryGetValue(identityDictionaryRef, unsafeAddressOf(kSecTrustResultValue))
        
        print("\(trustPointer.hashValue)")
        
        //MARK: Get Certificate and copy summary object
        
        let secIdentity: SecIdentityRef = unsafeBitCast(identityPointer, SecIdentityRef.self)
        
        getCertificate(secIdentity)
        
        //MARK: Get private key
        
        getPrivateKey(secIdentity)
        
        //MARK: Add Identity into keychain
        
        let cfDataRef = persistIdentityInKeyChain(secIdentity)
        
        //MARK: Fetch identity from keychain
        
        getIdentityFromKeychainUsingPersistenceRef(cfDataRef)
        
        
        //MARK: Get certificate from keychain
        let secCertRef = findCertificateInKeyChain()
        
        
        //MARK: Get policy and evaluate trust
        
        getPolicyObjectAndEvaluateTrust(secCertRef)
        
        return osStatus
    }
    
    func getCertificate(secIdentity: SecIdentityRef) -> OSStatus {
        
        var cert = SecCertificate?()
        
        let osStatus = SecIdentityCopyCertificate(secIdentity, &cert)
        
        if osStatus != 0 {
            
            print("No certificate fetched")
            NSLog("Certificate is not retrieved ", osStatus)
            
            return osStatus
            
        }else {
            
            print("Certificate successfully retrived!!")
            
        }
        
        //Get certificate summary
        let cfString = SecCertificateCopySubjectSummary(cert!)
        
        print("Subject summary is:  \(cfString)")
        //NSString* cfString = [[NSString alloc] initWithString:(__bridge NSString *)cfString]
        
        return osStatus
    }
    

    func getPrivateKey(secIdentity: SecIdentityRef) -> OSStatus {
    
        
        var secKeyPointer = SecKeyRef?()
        
        let osStatus = SecIdentityCopyPrivateKey(secIdentity, &secKeyPointer)
        
        if osStatus == 0 {
        
            print("Private key is: \(secKeyPointer)")
            
        }else{
            print("No certificate fetched")
            NSLog("Certificate is not retrieved ", osStatus)
        }
        
        
        return osStatus
    }
    
    func persistIdentityInKeyChain(secIdentity: SecIdentityRef) -> CFDataRef {
    
        var persistenceRef = AnyObject?()
        
        var keys = [unsafeAddressOf(kSecReturnPersistentRef as NSString), unsafeAddressOf(kSecValueRef as NSString)]
        var values = [unsafeAddressOf(kCFBooleanTrue), unsafeAddressOf(secIdentity)]
        
        let optionDictionary: CFDictionaryRef = CFDictionaryCreate(nil, &keys, &values, 2, nil, nil);
        
        let delResult = SecItemDelete(optionDictionary)
        
        if delResult == errSecSuccess {
            
            print("Identity already exist into keychain and it is removed")
            
        } else {
            
            NSLog("Identity does not exist into keychain")
        }
        
        let osStatus = SecItemAdd(optionDictionary, &persistenceRef)
        
        if osStatus != 0 {
            
          print("Error while adding identity into keychain")
        
        }else{
            
            print("Identity is stored successfully in Keychain")
        }
        
        return persistenceRef as! CFDataRef
    }
    
    func getIdentityFromKeychainUsingPersistenceRef(cfDataRef: CFDataRef) -> SecIdentityRef {
    
        var persistenceRef = AnyObject?()
       
        var keys = [unsafeAddressOf(kSecClass as NSString), unsafeAddressOf(kSecReturnRef as NSString), unsafeAddressOf(kSecValuePersistentRef as NSString)]
        var values = [unsafeAddressOf(kSecClassIdentity), unsafeAddressOf(kCFBooleanTrue), unsafeAddressOf(cfDataRef)]
        
        let optionDictionary: CFDictionaryRef = CFDictionaryCreate(nil, &keys, &values, 2, nil, nil);
        
       
        let osStatus = SecItemCopyMatching(optionDictionary, &persistenceRef)
        
        if osStatus != 0 {
        
            print("No identity in keychain")
            
        } else {
            
         print("Identity is retrieved successfully from Keychain")
        
        }
        
        return persistenceRef as! SecIdentityRef
    
    }
    
    func findCertificateInKeyChain()-> SecCertificateRef  {
        
        var persistenceRef = AnyObject?()
        
        let certLabel = CFStringCreateWithCString(nil, "AuthServer", kCFStringEncodingASCII)
        
        var keys = [unsafeAddressOf(kSecClass as NSString), unsafeAddressOf(kSecAttrLabel as NSString), unsafeAddressOf(kSecReturnRef as NSString)]
        var values = [unsafeAddressOf(kSecClassCertificate), unsafeAddressOf(certLabel), unsafeAddressOf(kCFBooleanTrue)]
        
        let optionDictionary: CFDictionaryRef = CFDictionaryCreate(nil, &keys, &values, 3, nil, nil);
        
        
        let osStatus = SecItemCopyMatching(optionDictionary, &persistenceRef)
        
        if osStatus != 0 {
            
            print("No certificate in keychain")
            
        } else {
            
            print("Certificate is retrieved successfully from Keychain")
            
        }
        
        return persistenceRef as! SecCertificateRef
    }
    
    func getPolicyObjectAndEvaluateTrust( secCert: SecCertificateRef) {
    
        var secTrustRef = SecTrustRef?()
        var secTrustResult = SecTrustResultType()
        
        let secPolicy = SecPolicyCreateBasicX509()
        
        var values = [unsafeAddressOf(secCert)]
        
        let cfArray: CFArrayRef = CFArrayCreate(nil, &values, 1, nil)
        
        var osStatus = SecTrustCreateWithCertificates(cfArray, secPolicy, &secTrustRef)
    
        if osStatus == 0 {
        
            print("Trust is created successfully")
            
            osStatus = SecTrustEvaluate(secTrustRef!, &secTrustResult)
            
            //kSecTrustResultProceed
            if (Int(secTrustResult) == kSecTrustResultRecoverableTrustFailure) {
            
                print("Certificate is not trusted")
                
            }else{
            
                print("Certificate is evaluated successfully")
            }
            
            
        }else {
        
            print("Trust is not created!!")
        }
    
    }
    
    
}