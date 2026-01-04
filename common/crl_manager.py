import json
import os

class CRLManager:
    """
    Gerencia a Lista de Revogação de Certificados (CRL) armazenada em um arquivo JSON.
    Rastreia números de série de certificados X.509 revogados.
    """
    def __init__(self, crl_path="crl.json"):
        """
        Inicializa o gerenciador CRL.
        
        :param crl_path: Caminho para o arquivo JSON da CRL.
        """
        self.crl_path = crl_path
        self.revoked_serials = set()
        self._load()

    def _load(self):
        """Carrega a CRL do arquivo se existir."""
        if os.path.exists(self.crl_path):
            try:
                with open(self.crl_path, 'r') as f:
                    data = json.load(f)
                    self.revoked_serials = set(int(s) for s in data.get('revoked', []))
                print(f"[CRL] Carregados {len(self.revoked_serials)} certificados revogados de {self.crl_path}")
            except Exception as e:
                print(f"[CRL] Falha ao carregar CRL: {e}")
                self.revoked_serials = set()
        else:
            print(f"[CRL] Arquivo CRL não encontrado em {self.crl_path}, inicializando vazio.")

    def save(self):
        """Salva a CRL atual no arquivo."""
        try:
            data = {
                'revoked': list(self.revoked_serials),
                'version': 1
            }
            with open(self.crl_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"[CRL] Salvas {len(self.revoked_serials)} entradas em {self.crl_path}")
        except Exception as e:
            print(f"[CRL] Falha ao salvar CRL: {e}")

    def is_revoked(self, serial_number):
        """
        Verifica se um número de série está na lista de revogação.
        
        :param serial_number: Número de série do certificado.
        :return: True se revogado, False caso contrário.
        """
        if not isinstance(serial_number, int):
            try:
                serial_number = int(serial_number)
            except:
                print(f"[CRL] Aviso: formato de serial inválido {serial_number}")
                return False
                
        is_revoked = serial_number in self.revoked_serials
        if is_revoked:
             print(f"[CRL] CERTIFICADO REVOGADO DETECTADO: Serial {serial_number}")
        
        return is_revoked

    def revoke(self, serial_number):
        """
        Adiciona um número de série à lista de revogação.
        
        :param serial_number: Número de série a revogar.
        """
        if not isinstance(serial_number, int):
             try:
                 serial_number = int(serial_number)
             except:
                 raise ValueError("Número de série deve ser um inteiro")
                 
        if serial_number not in self.revoked_serials:
            self.revoked_serials.add(serial_number)
            self.save()
            print(f"[CRL] Certificado revogado: {serial_number}")

    def update_from_list(self, new_serials):
        """
        Atualiza a lista de revogação com múltiplos seriais.
        
        :param new_serials: Lista de números de série.
        :return: True se houve alterações, False caso contrário.
        """
        added_count = 0
        for s in new_serials:
            try:
                s_int = int(s)
                if s_int not in self.revoked_serials:
                    self.revoked_serials.add(s_int)
                    added_count += 1
            except:
                pass
        
        if added_count > 0:
            self.save()
            print(f"[CRL] Atualizado com {added_count} novas revogações")
            return True
        return False

    def get_revoked_list(self):
        """Retorna lista de seriais revogados."""
        return list(self.revoked_serials)
