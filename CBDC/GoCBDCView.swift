//
//  GoCBDCView.swift
//  CBDC
//
//  Created by Hunter Chan on 16/4/2024.
//

import SwiftUI
import GoCBDC // 假设这是您的导入模块，用于调用 GoCBDCGO_CBDC 函数

struct GoCBDCView: View {
    let result: String
    init() {
        self.result = GoCBDCGO_CBDC()
    }

    var body: some View {
        ScrollView([.horizontal, .vertical]) { // 使用复合方向
            VStack(alignment: .leading) {
                Text(self.result)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .border(Color.gray, width: 1) // 可选，用于视觉区分边界
            }
            .background(Color.clear) // 防止VStack自动扩展高度
            .padding() // 可根据需要添加内边距
            .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
            .clipped() // 可选，剪裁超出部分
        }

    }
}

//#Preview {
//    GoCBDCView()
//}
