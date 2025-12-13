from pydbus import SystemBus

bus = SystemBus()
class TestObj:
    dbus = """
    <node>
        <interface name="org.test.Iface">
            <method name="Foo"/>
        </interface>
    </node>
    """
    def Foo(self): pass

obj = TestObj()
reg = bus.register_object("/org/test/obj", obj, None)
print("Registration type:", type(reg))
print("Registration dir:", dir(reg))
