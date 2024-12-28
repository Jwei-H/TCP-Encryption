package com.jingwei.encryption;

public class BaseMessage<T> {
    // 1为交互密钥，2为传输数据
    private final byte type;
    private final T content;

    public BaseMessage(byte type, T content) {
        this.type = type;
        this.content = content;
    }

    public byte getType() {
        return type;
    }

    public T getContent() {
        return content;
    }
}
