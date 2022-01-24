class Field:
    def __init__(self, layer, key, t=int, b=10, store_existance=False, to_csv=True, to_str=None) -> None:
        """Generates a layer field. 

        Args:
            layer (pyshark.Layer): Parent layer object to get the fields from
            key (string): The name of the field
            t (type, optional): The type that we want to store the field as. Defaults to int.
            b (int, optional): In case this is an integer type, the base to parse it to. Defaults to 10.
            store_existance (bool, optional): [description]. Defaults to False.
            to_csv (bool, optional): Should this field be included in the csv? Defaults to True.
            to_str ([type], optional): How to print this field. Defaults to None.
        """
        self.key = key
        if store_existance:
            self.value = 1 if layer.get(key) is not None else 0
        elif t == int:
            self.value = t(layer.get(key) or '0', b)
        elif t == str:
            self.value = layer.get(key) or ""
        else:
            self.value = t(layer.get(key) or 0)
        self.to_csv = to_csv
        self.str_value = to_str

    def add_to_csv(self):
        return self.to_csv
    def get_key(self):
        return self.key
    def get_value(self):
        return self.value
        
    def __str__(self,):
        v = self.value
        if self.to_str:
            v = self.to_str if type(
                self.to_str) == str else self.to_str(self.value)
        return '{}: {}'.format(self.key, v)
