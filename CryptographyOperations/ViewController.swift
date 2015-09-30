//
//  ViewController.swift
//  CryptographyOperations
//
//  Created by Bhaidas Masule on 04/09/2015.
//  Copyright (c) 2015 NGO. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        let identityReader = IdentityFileReader()
        identityReader.readePKCS12File()
        
        
        //let createKeyPair = CreateKeyPair()
        //createKeyPair.generateKeyPair()
        //createKeyPair.findKey(tag:"myPublicKey")
        //createKeyPair.findKey(tag:"myPrivateKey")
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

