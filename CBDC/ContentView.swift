//
//  ContentView.swift
//  CBDC
//
//  Created by Hunter Chan on 7/3/2024.
//

import SwiftUI


struct ContentView: View {
    var body: some View {
        NavigationView {
            VStack {
                NavigationLink(destination: GoCBDCView()) {
                    Text("TEST")
                }
            }
        }
    }
}

//#Preview {
//    ContentView()
//}
