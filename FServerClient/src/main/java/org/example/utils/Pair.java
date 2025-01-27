package org.example.utils;

public class Pair<K,V> {
    K first;
    V second;

    public Pair(K f, V s){
        first = f;
        second = s;
    }

    public K getFirst() {
        return first;
    }

    public V getSecond() {
        return second;
    }
}
