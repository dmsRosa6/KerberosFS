package org.example;

/*
 * This class is used to pre-install and check the accesses of the users in the system. And its not used in the project at runtime. This is used to test the
 * module logic too.
 */
public class InstallAccesses {

    public static void main(String[] args) {
        //AccessControl.addPermission("alice", "r");
        //AccessControl.getUserPermissions().forEach((k, v) -> System.out.println(k + " " + v));
        AccessControl a = new AccessControl();
        System.out.println(a.hasPermission("alice", "put"));
    }
}
