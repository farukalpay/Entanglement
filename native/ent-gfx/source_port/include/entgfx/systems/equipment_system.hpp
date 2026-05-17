
#pragma once

#include "entgfx/systems/inventory_system.hpp"

#include <string>

namespace entgfx {

class EquipmentSystem {
public:
  void clear();
  void equip(ItemStack stack);
  void equipFromHotbar(const Hotbar &hotbar);

  [[nodiscard]] const ItemStack &equipped() const;
  [[nodiscard]] bool hasEquippedItem() const;
  [[nodiscard]] bool isEquipped(const std::string &item_id) const;

private:
  ItemStack equipped_{};
};

} // namespace entgfx
